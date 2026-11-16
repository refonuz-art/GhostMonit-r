//! IPC for File Intelligence, hash DB, reputation providers, startup, terminal and reports.

use std::sync::Arc;

use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, State};

use crate::model::{AddrScope, ConnectionInfo, Severity};
use crate::monitor::{emit_event, event};
use crate::state::Shared;

type S<'a> = State<'a, Arc<Shared>>;
type R<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

// ---------------- file intelligence ----------------

#[tauri::command]
pub async fn analyze_file(s: State<'_, Arc<Shared>>, path: String) -> R<crate::intel::file::FileReport> {
    let shared = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        crate::intel::file::analyze(
            &path,
            |p| shared.sigs.verify_now(p),
            |h| crate::intel::hashdb::lookup(&shared.store.lock().conn, h),
        )
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub fn hashdb_stats(s: S) -> R<crate::intel::hashdb::HashDbStats> {
    crate::intel::hashdb::stats(&s.store.lock().conn).map_err(err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    added: u64,
    seen: u64,
}

#[tauri::command]
pub async fn hashdb_import(app: AppHandle, s: State<'_, Arc<Shared>>, path: String) -> R<ImportResult> {
    let shared = s.inner().clone();
    let (added, seen) = tauri::async_runtime::spawn_blocking(move || {
        crate::intel::hashdb::import(&shared.store.lock().conn, std::path::Path::new(&path))
    })
    .await
    .map_err(err)??;
    emit_event(
        &app,
        &s,
        event(
            "user.hashdb",
            Severity::Info,
            format!("Zararlı hash veritabanına {added} kayıt eklendi"),
            format!("{seen} hash okundu"),
            None,
            json!({ "added": added, "seen": seen }),
        ),
    );
    Ok(ImportResult { added, seen })
}

#[tauri::command]
pub fn hashdb_clear(s: S) -> R<usize> {
    crate::intel::hashdb::clear(&s.store.lock().conn).map_err(err)
}

const VT_SECRET: &str = "virustotal";

pub(crate) fn secret(s: &Shared, name: &str) -> Option<String> {
    let blob: Vec<u8> = s
        .store
        .lock()
        .conn
        .query_row("SELECT blob FROM secrets WHERE name=?1", [name], |r| r.get(0))
        .ok()?;
    crate::winapi::dpapi::unprotect(&blob).ok().and_then(|b| String::from_utf8(b).ok())
}

/// Store (DPAPI-encrypted, bound to this Windows user) or delete an API key.
fn set_secret(s: &Shared, name: &str, key: Option<String>) -> R<()> {
    let st = s.store.lock();
    match key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty()) {
        Some(k) => {
            if k.len() < 32 || !k.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err("Anahtar biçimi geçersiz görünüyor".into());
            }
            let blob = crate::winapi::dpapi::protect(k.as_bytes())?;
            st.conn
                .execute("INSERT OR REPLACE INTO secrets (name, blob) VALUES (?1, ?2)", rusqlite::params![name, blob])
                .map_err(err)?;
        }
        None => {
            st.conn.execute("DELETE FROM secrets WHERE name=?1", [name]).map_err(err)?;
        }
    }
    Ok(())
}

#[tauri::command]
pub fn vt_has_key(s: S) -> bool {
    secret(&s, VT_SECRET).is_some()
}

#[tauri::command]
pub fn vt_set_key(s: S, key: Option<String>) -> R<()> {
    set_secret(&s, VT_SECRET, key)
}

#[tauri::command]
pub fn abuse_has_key(s: S) -> bool {
    secret(&s, crate::watchers::ABUSE_SECRET).is_some()
}

#[tauri::command]
pub fn abuse_set_key(s: S, key: Option<String>) -> R<()> {
    set_secret(&s, crate::watchers::ABUSE_SECRET, key)
}

#[tauri::command]
pub async fn feed_update_now(app: AppHandle, s: State<'_, Arc<Shared>>) -> R<crate::watchers::FeedResult> {
    let shared = s.inner().clone();
    let r = tauri::async_runtime::spawn_blocking(move || crate::watchers::update_feed(&shared)).await.map_err(err)??;
    crate::monitor::emit_event(
        &app,
        &s,
        crate::monitor::event(
            "intel.feed",
            crate::model::Severity::Info,
            format!("Kötü amaçlı yazılım listesi güncellendi: {} yeni", r.added),
            format!("MalwareBazaar son 48 saat: {} hash, {} tanesi yeni. Yerel veritabanında toplam {}.", r.seen, r.added, r.total),
            None,
            serde_json::json!({}),
        ),
    );
    Ok(r)
}

#[tauri::command]
pub fn auto_scans(s: S) -> Vec<crate::watchers::AutoScan> {
    s.auto_scans.read().clone()
}

#[tauri::command]
pub fn drives(s: S) -> Vec<crate::watchers::DriveInfo> {
    s.drives.read().clone()
}

#[tauri::command]
pub async fn vt_lookup(s: State<'_, Arc<Shared>>, sha256: String) -> R<crate::intel::providers::Reputation> {
    use crate::intel::providers::{IntelProvider, VirusTotal};
    let key = secret(&s, VT_SECRET).ok_or("VirusTotal API anahtarı tanımlı değil")?;
    tauri::async_runtime::spawn_blocking(move || VirusTotal { key }.lookup_sha256(&sha256))
        .await
        .map_err(err)?
}

// ---------------- startup ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupSnapshot {
    items: Vec<crate::collectors::startup::StartupItem>,
    scanned_at: Option<i64>,
}

#[tauri::command]
pub fn startup_items(s: S) -> StartupSnapshot {
    StartupSnapshot { items: s.startup.read().clone(), scanned_at: *s.startup_scanned_at.read() }
}

#[tauri::command]
pub fn rescan_startup(s: S) -> R<()> {
    s.startup_rescan.lock().as_ref().ok_or("tarayıcı çalışmıyor")?.send(()).map_err(err)
}

// ---------------- terminal: ip ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpInfo {
    ip: String,
    scope: String,
    hostname: Option<String>,
    country: Option<String>,
    asn: Option<String>,
    live: Vec<ConnectionInfo>,
    seen_count: i64,
    first_seen: Option<i64>,
    last_seen: Option<i64>,
    processes: Option<String>,
}

#[tauri::command]
pub async fn ip_info(s: State<'_, Arc<Shared>>, ip: String) -> R<IpInfo> {
    let addr: std::net::IpAddr = ip.trim().parse().map_err(|_| "Geçerli bir IPv4/IPv6 adresi değil".to_string())?;
    let shared = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let hostname = shared.rdns.resolve_now(addr);
        let g = shared.geo.lookup(addr);
        let ipstr = addr.to_string();
        let live: Vec<ConnectionInfo> =
            shared.connections.read().iter().filter(|c| c.remote_addr.as_deref() == Some(ipstr.as_str())).cloned().collect();
        let (seen_count, first_seen, last_seen, processes) = shared
            .store
            .lock()
            .conn
            .query_row(
                "SELECT COUNT(*), MIN(ts), MAX(ts), GROUP_CONCAT(DISTINCT process) FROM conn_history WHERE remote=?1",
                [&ipstr],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(err)?;
        let scope = match crate::collectors::network::scope_of(&addr) {
            AddrScope::Loopback => "bu bilgisayar",
            AddrScope::Private => "yerel ağ",
            AddrScope::Public => "internet",
            AddrScope::Unspecified => "belirsiz",
        };
        Ok(IpInfo {
            ip: ipstr,
            scope: scope.into(),
            hostname,
            country: g.country,
            asn: g.asn,
            live,
            seen_count,
            first_seen,
            last_seen,
            processes,
        })
    })
    .await
    .map_err(err)?
}

// ---------------- reports ----------------

fn period(kind: &str, since: Option<i64>, until: Option<i64>) -> (i64, i64) {
    let now = chrono::Utc::now().timestamp_millis();
    let until = until.unwrap_or(now);
    let since = since.unwrap_or(match kind {
        "weekly" => until - 7 * 86_400_000,
        _ => until - 86_400_000,
    });
    (since, until)
}

#[tauri::command]
pub async fn build_report(
    s: State<'_, Arc<Shared>>,
    kind: String,
    since: Option<i64>,
    until: Option<i64>,
) -> R<crate::report::ReportData> {
    let shared = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (a, b) = period(&kind, since, until);
        crate::report::build(&shared, &kind, a, b)
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn export_report(
    s: State<'_, Arc<Shared>>,
    kind: String,
    format: String,
    path: String,
    since: Option<i64>,
    until: Option<i64>,
) -> R<String> {
    let shared = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (a, b) = period(&kind, since, until);
        let data = crate::report::build(&shared, &kind, a, b)?;
        match format.as_str() {
            "json" => crate::report::write_json(&data, &path)?,
            "pdf" => crate::report::write_pdf(&data, &path)?,
            _ => return Err("Bilinmeyen biçim".to_string()),
        }
        Ok(path)
    })
    .await
    .map_err(err)?
}
