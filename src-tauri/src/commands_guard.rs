//! IPC for the 0.3 protection modules (guard/*).

use std::sync::Arc;

use serde_json::json;
use tauri::{AppHandle, State};

use crate::guard::{self, firewall, quarantine, remote};
use crate::model::Severity;
use crate::monitor::{emit_event, event};
use crate::state::Shared;

type S<'a> = State<'a, Arc<Shared>>;
type R<T> = Result<T, String>;

fn join<T>(r: Result<R<T>, tauri::Error>) -> R<T> {
    r.map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn guard_state(s: S) -> guard::GuardState {
    s.guard.read().clone()
}

/// Re-run one check now. `what`: defender | browser | netconf | lan | eventlog | health
#[tauri::command]
pub async fn guard_refresh(app: AppHandle, s: State<'_, Arc<Shared>>, what: String) -> R<guard::GuardState> {
    let shared = s.inner().clone();
    let a = app.clone();
    join(
        tauri::async_runtime::spawn_blocking(move || {
            match what.as_str() {
                "defender" => guard::defender::tick(&a, &shared),
                "browser" => guard::browser::tick(&a, &shared),
                "netconf" => guard::netconf::tick(&a, &shared),
                "lan" => guard::lan::tick(&a, &shared),
                "eventlog" => guard::eventlog::tick(&a, &shared),
                "health" => {}
                _ => return Err("Bilinmeyen kontrol".to_string()),
            }
            guard::health::refresh(&shared);
            guard::emit(&a, &shared);
            Ok(shared.guard.read().clone())
        })
        .await,
    )
}

// ---------------- firewall ----------------

#[tauri::command]
pub fn fw_rules(s: S) -> Vec<firewall::BlockRule> {
    firewall::rules(&s)
}

#[tauri::command]
pub async fn fw_block(app: AppHandle, s: State<'_, Arc<Shared>>, kind: String, target: String) -> R<firewall::BlockRule> {
    let shared = s.inner().clone();
    let rule = join(tauri::async_runtime::spawn_blocking(move || firewall::block(&shared, &kind, &target)).await)?;
    emit_event(
        &app,
        &s,
        event(
            "user.block",
            Severity::Info,
            format!("Güvenlik duvarında engellendi: {}", rule.target),
            if crate::winapi::elevation::is_elevated() { "Gelen ve giden bağlantılar engellendi".into() } else { "Giden bağlantılar engellendi".into() },
            Some(rule.target.clone()),
            json!({ "rule": rule.name, "kind": rule.kind }),
        ),
    );
    Ok(rule)
}

#[tauri::command]
pub async fn fw_unblock(app: AppHandle, s: State<'_, Arc<Shared>>, name: String) -> R<()> {
    let shared = s.inner().clone();
    let n = name.clone();
    join(tauri::async_runtime::spawn_blocking(move || firewall::unblock(&shared, &n)).await)?;
    emit_event(&app, &s, event("user.block", Severity::Info, format!("Engelleme kaldırıldı: {name}"), String::new(), None, json!({})));
    Ok(())
}

// ---------------- quarantine ----------------

#[tauri::command]
pub fn quarantine_list(s: S) -> R<Vec<quarantine::QItem>> {
    quarantine::list(&s)
}

#[tauri::command]
pub async fn quarantine_add(app: AppHandle, s: State<'_, Arc<Shared>>, path: String, reason: Option<String>) -> R<quarantine::QItem> {
    let shared = s.inner().clone();
    let reason = reason.unwrap_or_default().chars().take(200).collect::<String>();
    let item = join(tauri::async_runtime::spawn_blocking(move || quarantine::add(&shared, &path, &reason)).await)?;
    // A quarantined file's findings no longer apply.
    s.watch_findings.write().retain(|f| f.entity != item.original);
    emit_event(
        &app,
        &s,
        event("user.quarantine", Severity::Info, format!("Karantinaya alındı: {}", item.original), format!("SHA-256 {}", item.sha256), Some(item.original.clone()), json!({ "id": item.id })),
    );
    Ok(item)
}

#[tauri::command]
pub async fn quarantine_restore(app: AppHandle, s: State<'_, Arc<Shared>>, id: i64) -> R<String> {
    let shared = s.inner().clone();
    let path = join(tauri::async_runtime::spawn_blocking(move || quarantine::restore(&shared, id)).await)?;
    emit_event(&app, &s, event("user.quarantine", Severity::Low, format!("Karantinadan geri yüklendi: {path}"), String::new(), Some(path.clone()), json!({ "id": id })));
    Ok(path)
}

#[tauri::command]
pub fn quarantine_delete(app: AppHandle, s: S, id: i64) -> R<()> {
    quarantine::delete(&s, id)?;
    emit_event(&app, &s, event("user.quarantine", Severity::Info, "Karantinadaki dosya kalıcı olarak silindi".into(), String::new(), None, json!({ "id": id })));
    Ok(())
}

// ---------------- remote notifications ----------------

#[tauri::command]
pub fn remote_status(s: S) -> remote::RemoteStatus {
    remote::status(&s)
}

#[tauri::command]
pub fn remote_set_telegram(s: S, token: Option<String>, chat: Option<String>) -> R<()> {
    remote::set_telegram(&s, token, chat)
}

#[tauri::command]
pub fn remote_set_discord(s: S, url: Option<String>) -> R<()> {
    remote::set_discord(&s, url)
}

#[tauri::command]
pub async fn remote_test(s: State<'_, Arc<Shared>>) -> R<usize> {
    let shared = s.inner().clone();
    join(tauri::async_runtime::spawn_blocking(move || remote::test(&shared)).await)
}

// ---------------- network ----------------

#[tauri::command]
pub async fn lan_sweep(app: AppHandle, s: State<'_, Arc<Shared>>) -> R<usize> {
    let shared = s.inner().clone();
    join(
        tauri::async_runtime::spawn_blocking(move || {
            let n = guard::lan::sweep()?;
            guard::lan::tick(&app, &shared);
            Ok(n)
        })
        .await,
    )
}

#[tauri::command]
pub async fn net_usage(s: State<'_, Arc<Shared>>) -> R<guard::netstats::NetUsage> {
    let shared = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let u = guard::netstats::sample(&shared);
        *shared.net_usage.write() = u.clone();
        u
    })
    .await
    .map_err(|e| e.to_string())
}

// ---------------- suspend / resume ----------------

#[link(name = "ntdll")]
extern "system" {
    fn NtSuspendProcess(h: windows::Win32::Foundation::HANDLE) -> i32;
    fn NtResumeProcess(h: windows::Win32::Foundation::HANDLE) -> i32;
}

/// Freeze (or thaw) a process without killing it — the safe first response to ransomware.
#[tauri::command]
pub fn suspend_process(app: AppHandle, s: S, pid: u32, suspend: bool) -> R<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};
    if pid <= 4 || pid == std::process::id() {
        return Err("Bu işlem korumalıdır".into());
    }
    let p = s.processes.read().iter().find(|p| p.pid == pid).cloned().ok_or("İşlem bulunamadı (kapanmış olabilir)")?;
    if p.critical && suspend {
        return Err(format!("{} kritik bir sistem işlemidir; dondurmak Windows'u kilitler", p.name));
    }
    let status = unsafe {
        let h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid).map_err(|e| {
            if e.code().0 as u32 == 0x80070005 { "Erişim reddedildi — yönetici yetkisi gerekiyor".to_string() } else { e.message() }
        })?;
        let st = if suspend { NtSuspendProcess(h) } else { NtResumeProcess(h) };
        let _ = CloseHandle(h);
        st
    };
    if status != 0 {
        return Err(format!("İşlem {} (NTSTATUS 0x{status:08X})", if suspend { "dondurulamadı" } else { "devam ettirilemedi" }));
    }
    let msg = format!("{} (PID {pid}) {}", p.name, if suspend { "donduruldu" } else { "devam ettirildi" });
    emit_event(&app, &s, event("process.suspend", Severity::Low, msg.clone(), p.exe.clone().unwrap_or_default(), Some(p.name.clone()), json!({ "pid": pid, "suspend": suspend })));
    Ok(msg)
}
