//! Protective checks added in 0.3: ransomware shield, browser extensions, hosts/DNS/proxy,
//! Defender & firewall, Windows event log, firewall blocking, LAN devices, per-process
//! network usage, phone notifications, quarantine and the health score.

pub mod browser;
pub mod canary;
pub mod defender;
pub mod dnslog;
pub mod eventlog;
pub mod firewall;
pub mod health;
pub mod lan;
pub mod netconf;
pub mod netstats;
pub mod quarantine;
pub mod remote;

use std::os::windows::process::CommandExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::engine::score;
use crate::model::{Finding, Severity, Signal};
use crate::state::Shared;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Everything the Health module shows, refreshed by the guard thread.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardState {
    pub defender: Option<defender::SecurityStatus>,
    pub netconf: Option<netconf::NetConf>,
    pub extensions: Vec<browser::Extension>,
    pub extensions_scanned: Option<i64>,
    pub lan: Vec<lan::LanDevice>,
    pub lan_scanned: Option<i64>,
    pub canary: canary::CanaryStatus,
    pub eventlog: eventlog::EventLogStatus,
    pub health: Option<health::HealthReport>,
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Run a console program without flashing a window. Returns (exit code, stdout).
pub fn run_hidden(exe: &str, args: &[&str], timeout: Duration) -> Result<(i32, String), String> {
    let mut child = std::process::Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{exe} başlatılamadı: {e}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() > timeout => {
                let _ = child.kill();
                return Err(format!("{exe} zaman aşımına uğradı"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(e.to_string()),
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let text = decode_console(&out.stdout);
    Ok((out.status.code().unwrap_or(-1), text))
}

/// Console tools print in the OEM code page (857 on Turkish Windows); PowerShell we force to UTF-8.
fn decode_console(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.trim_start_matches('\u{feff}').to_string(),
        Err(_) => b.iter().map(|&c| if c < 128 { c as char } else { cp857(c) }).collect(),
    }
}

fn cp857(c: u8) -> char {
    match c {
        0x80 => 'Ç', 0x81 => 'ü', 0x87 => 'ç', 0x8D => 'ı', 0x94 => 'ö', 0x98 => 'İ', 0x99 => 'Ö',
        0x9A => 'Ü', 0x9E => 'Ş', 0x9F => 'ş', 0xA6 => 'Ğ', 0xA7 => 'ğ', 0x82 => 'é', 0x85 => 'à',
        _ => '?',
    }
}

/// PowerShell with UTF-8 output and no profile; the script is passed as -Command.
pub fn powershell(script: &str, timeout: Duration) -> Result<String, String> {
    let full = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; {script}");
    let (code, out) = run_hidden("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", &full], timeout)?;
    if code != 0 && out.trim().is_empty() {
        return Err(format!("PowerShell çıkış kodu {code}"));
    }
    Ok(out)
}

/// Build a finding from signals (None when there are none).
pub fn finding(key: &str, kind: &str, entity: &str, title: String, signals: Vec<Signal>, pids: Vec<u32>) -> Option<Finding> {
    if signals.is_empty() {
        return None;
    }
    let (sc, sev) = score(&signals);
    let now = now_ms();
    Some(Finding {
        key: key.into(),
        entity_kind: kind.into(),
        entity: entity.into(),
        title,
        severity: sev,
        score: sc,
        signals,
        first_seen: now,
        last_seen: now,
        pid: pids.first().copied(),
        pids,
        status: "open".into(),
    })
}

/// Replace every finding whose key starts with `prefix` by `items`.
pub fn set_findings(shared: &Shared, prefix: &str, items: Vec<Finding>) {
    let trusted: std::collections::HashSet<String> = shared.store.lock().trusted().unwrap_or_default().into_iter().collect();
    let mut w = shared.watch_findings.write();
    w.retain(|f| !f.key.starts_with(prefix));
    w.extend(items.into_iter().filter(|f| !trusted.contains(&f.key)));
}

pub fn emit(app: &AppHandle, shared: &Shared) {
    let _ = app.emit("gm://guard", &*shared.guard.read());
}

pub fn severity_of(signals: &[Signal]) -> Severity {
    if signals.is_empty() {
        Severity::Info
    } else {
        score(signals).1
    }
}

/// One scheduler thread for the periodic checks; the ransomware watchers have their own.
pub fn spawn(app: AppHandle, shared: Arc<Shared>) {
    canary::spawn(app.clone(), shared.clone());
    std::thread::Builder::new()
        .name("guard".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(10));
            let mut last: [Option<Instant>; 6] = [None; 6];
            let due = |slot: &mut Option<Instant>, every: Duration| -> bool {
                if slot.is_none_or(|t| t.elapsed() >= every) {
                    *slot = Some(Instant::now());
                    true
                } else {
                    false
                }
            };
            loop {
                let s = shared.settings.read().clone();
                if due(&mut last[0], Duration::from_secs(60)) {
                    netconf::tick(&app, &shared);
                }
                if due(&mut last[1], Duration::from_secs(600)) {
                    defender::tick(&app, &shared);
                }
                if due(&mut last[2], Duration::from_secs(300)) {
                    browser::tick(&app, &shared);
                }
                if s.eventlog_watch && due(&mut last[3], Duration::from_secs(30)) {
                    eventlog::tick(&app, &shared);
                }
                if s.lan_watch && due(&mut last[4], Duration::from_secs(60)) {
                    lan::tick(&app, &shared);
                }
                if due(&mut last[5], Duration::from_secs(120)) {
                    health::refresh(&shared);
                    emit(&app, &shared);
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        })
        .expect("spawn guard");
}
