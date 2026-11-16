//! IPC surface exposed to the frontend.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, State};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

use crate::model::{ConnectionInfo, Finding, HostInfo, ProcessInfo, SecurityEvent, Severity, SystemMetrics};
use crate::monitor::{emit_event, event};
use crate::state::Shared;
use crate::winapi::elevation;

type S<'a> = State<'a, Arc<Shared>>;
type R<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    host: HostInfo,
    metrics: Option<SystemMetrics>,
    processes: Vec<ProcessInfo>,
    connections: Vec<ConnectionInfo>,
    findings: Vec<Finding>,
}

#[tauri::command]
pub fn get_snapshot(s: S) -> Snapshot {
    Snapshot {
        host: s.host.read().clone(),
        metrics: s.metrics.read().clone(),
        processes: s.processes.read().clone(),
        connections: s.connections.read().clone(),
        findings: s.findings.read().clone(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventQuery {
    since: Option<i64>,
    until: Option<i64>,
    #[serde(default)]
    kinds: Vec<String>,
    min_severity: Option<Severity>,
    search: Option<String>,
    limit: Option<u32>,
}

#[tauri::command]
pub fn get_events(s: S, q: EventQuery) -> R<Vec<SecurityEvent>> {
    s.store
        .lock()
        .events(q.since, q.until, &q.kinds, q.min_severity, q.search.as_deref(), q.limit.unwrap_or(500).min(5000))
        .map_err(err)
}

#[tauri::command]
pub fn get_finding_history(s: S, limit: Option<u32>) -> R<Vec<Finding>> {
    s.store.lock().finding_history(limit.unwrap_or(500)).map_err(err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KillResult {
    ok: bool,
    /// "confirm" → caller must ask the user and retry with confirmed=true
    needs: Option<String>,
    message: String,
}

#[tauri::command]
pub fn kill_process(app: AppHandle, s: S, pid: u32, confirmed: bool) -> KillResult {
    let target = s.processes.read().iter().find(|p| p.pid == pid).cloned();
    let Some(p) = target else {
        return KillResult { ok: false, needs: None, message: "İşlem bulunamadı (zaten sonlanmış olabilir)".into() };
    };
    if pid <= 4 || pid == std::process::id() {
        return KillResult { ok: false, needs: None, message: "Bu işlem korumalıdır ve sonlandırılamaz".into() };
    }
    if p.critical && !confirmed {
        return KillResult {
            ok: false,
            needs: Some("confirm".into()),
            message: format!("{} kritik bir sistem işlemidir. Sonlandırmak sistemi kararsız hale getirebilir.", p.name),
        };
    }
    let res = unsafe {
        OpenProcess(PROCESS_TERMINATE, false, pid).and_then(|h| {
            let r = TerminateProcess(h, 1);
            let _ = CloseHandle(h);
            r
        })
    };
    match res {
        Ok(()) => {
            emit_event(
                &app,
                &s,
                event(
                    "process.kill",
                    Severity::Low,
                    format!("İşlem kullanıcı tarafından sonlandırıldı: {}", p.name),
                    p.exe.clone().unwrap_or_default(),
                    Some(p.name.clone()),
                    json!({ "pid": pid, "exe": p.exe }),
                ),
            );
            KillResult { ok: true, needs: None, message: format!("{} (PID {}) sonlandırıldı", p.name, pid) }
        }
        Err(e) => {
            let access = e.code().0 as u32 == 0x80070005;
            KillResult {
                ok: false,
                needs: access.then(|| "admin".into()),
                message: if access {
                    "Erişim reddedildi — bu işlem için yönetici yetkisi gerekiyor".into()
                } else {
                    format!("Sonlandırılamadı: {}", e.message())
                },
            }
        }
    }
}

#[tauri::command]
pub fn set_trust(app: AppHandle, s: S, key: String, trusted: bool) -> R<()> {
    s.store.lock().set_trust(&key, trusted, None).map_err(err)?;
    if trusted {
        s.findings.write().retain(|f| f.key != key);
        s.startup_findings.write().retain(|f| f.key != key);
        s.watch_findings.write().retain(|f| f.key != key);
        emit_event(
            &app,
            &s,
            event(
                "user.trust",
                Severity::Info,
                "Öğe güvenilir listesine eklendi".into(),
                key.clone(),
                None,
                json!({ "key": key }),
            ),
        );
    }
    Ok(())
}

#[tauri::command]
pub fn set_finding_status(s: S, key: String, status: String) -> R<()> {
    if !["open", "dismissed", "investigating"].contains(&status.as_str()) {
        return Err("geçersiz durum".into());
    }
    s.store.lock().set_finding_status(&key, &status).map_err(err)?;
    if status == "dismissed" {
        s.findings.write().retain(|f| f.key != key);
    }
    Ok(())
}

#[tauri::command]
pub fn set_background(s: S, background: bool) {
    s.background.store(background, Ordering::Relaxed);
}

#[tauri::command]
pub fn relaunch_admin(app: AppHandle) -> R<()> {
    elevation::relaunch_elevated()?;
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub fn get_settings(s: S) -> crate::settings::AppSettings {
    let mut v = s.settings.read().clone();
    v.autostart = crate::settings::autostart_enabled();
    v
}

#[tauri::command]
pub fn save_settings(s: S, mut settings: crate::settings::AppSettings) -> R<crate::settings::AppSettings> {
    settings.clamp();
    if settings.autostart != crate::settings::autostart_enabled() {
        crate::settings::set_autostart(settings.autostart)?;
    }
    settings.autostart = crate::settings::autostart_enabled();
    settings.save(&s.store.lock())?;
    let rescan = s.settings.read().startup_scan_minutes != settings.startup_scan_minutes;
    *s.settings.write() = settings.clone();
    if rescan {
        if let Some(tx) = s.startup_rescan.lock().as_ref() {
            let _ = tx.send(()); // pick up the new period
        }
    }
    Ok(settings)
}

/// Real exit (the window close button only hides to the tray).
#[tauri::command]
pub fn quit_app(app: AppHandle) {
    app.exit(0);
}

#[tauri::command]
pub fn reveal_in_explorer(path: String) -> R<()> {
    use std::os::windows::process::CommandExt;
    let p = std::path::Path::new(&path);
    if !p.is_absolute() || path.contains('"') || !p.exists() {
        return Err("Dosya bulunamadı".into());
    }
    // raw_arg + quotes: a file name containing commas must not be read as extra switches.
    std::process::Command::new("explorer.exe")
        .raw_arg(format!("/select,\"{}\"", p.display()))
        .spawn()
        .map(|_| ())
        .map_err(err)
}

#[tauri::command]
pub fn geo_status(s: S) -> crate::intel::geo::GeoStatus {
    s.geo.status()
}

#[tauri::command]
pub async fn download_geo(s: State<'_, Arc<Shared>>) -> R<crate::intel::geo::GeoStatus> {
    let shared = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || shared.geo.download())
        .await
        .map_err(err)?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnHistoryRow {
    ts: i64,
    pid: u32,
    process: Option<String>,
    exe: Option<String>,
    remote: String,
    port: u16,
    hostname: Option<String>,
    country: Option<String>,
    asn: Option<String>,
}

#[tauri::command]
pub fn conn_history(s: S, search: Option<String>, limit: Option<u32>) -> R<Vec<ConnHistoryRow>> {
    let st = s.store.lock();
    let like = format!("%{}%", search.unwrap_or_default());
    let mut stmt = st
        .conn
        .prepare(
            "SELECT ts, pid, process, exe, remote, port, hostname, country, asn FROM conn_history
             WHERE (process LIKE ?1 OR remote LIKE ?1 OR IFNULL(hostname,'') LIKE ?1 OR IFNULL(exe,'') LIKE ?1)
             ORDER BY ts DESC LIMIT ?2",
        )
        .map_err(err)?;
    let rows = stmt
        .query_map(rusqlite::params![like, limit.unwrap_or(500).min(5000)], |r| {
            Ok(ConnHistoryRow {
                ts: r.get(0)?,
                pid: r.get(1)?,
                process: r.get(2)?,
                exe: r.get(3)?,
                remote: r.get(4)?,
                port: r.get(5)?,
                hostname: r.get(6)?,
                country: r.get(7)?,
                asn: r.get(8)?,
            })
        })
        .map_err(err)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(err)
}
