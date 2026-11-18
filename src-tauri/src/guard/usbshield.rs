//! USB shield: a program started from a removable drive is frozen as soon as it is seen and
//! raised as a finding. Freezing is reversible (resume from the process screen or the
//! incident panel), so a legitimate portable program costs one click.

use std::collections::HashSet;

use parking_lot::Mutex;
use serde_json::json;
use tauri::AppHandle;

use super::now_ms;
use crate::model::{Finding, ProcessInfo, Severity, Signal};
use crate::monitor::{emit_event, event};
use crate::state::Shared;

#[link(name = "kernel32")]
extern "system" {
    fn GetDriveTypeW(root: *const u16) -> u32;
}
const DRIVE_REMOVABLE: u32 = 2;

/// Exes the user resumed: not frozen again until Ghost Monitor restarts.
static ALLOWED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

pub fn allow(exe: &str) {
    ALLOWED.lock().get_or_insert_with(HashSet::new).insert(exe.to_ascii_lowercase());
}

fn root_of(exe: &str) -> Option<String> {
    let b = exe.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        .then(|| format!("{}:\\", (b[0] as char).to_ascii_uppercase()))
}

pub fn on_removable(shared: &Shared, exe: &str) -> bool {
    let Some(root) = root_of(exe) else { return false };
    if shared.drives.read().iter().any(|d| d.letter.eq_ignore_ascii_case(&root)) {
        return true;
    }
    let w: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
    unsafe { GetDriveTypeW(w.as_ptr()) == DRIVE_REMOVABLE }
}

/// Called with the processes that appeared since the last tick.
pub fn check(app: &AppHandle, shared: &Shared, new: &[&ProcessInfo]) {
    if !shared.settings.read().usb_shield {
        return;
    }
    for p in new {
        let Some(exe) = &p.exe else { continue };
        if !on_removable(shared, exe) {
            continue;
        }
        if ALLOWED.lock().as_ref().is_some_and(|a| a.contains(&exe.to_ascii_lowercase())) {
            continue;
        }
        let res = crate::commands_guard::suspend_pid(shared, p.pid, true);
        let (title, sev) = match &res {
            Ok(_) => (format!("USB kalkanı: {} donduruldu", p.name), Severity::High),
            Err(_) => (format!("USB'den program çalıştı: {}", p.name), Severity::High),
        };
        let detail = match &res {
            Ok(_) => format!("{exe} çıkarılabilir sürücüden başlatıldı ve donduruldu. Güveniyorsanız İşlem Avcısı'ndan devam ettirin."),
            Err(e) => format!("{exe} çıkarılabilir sürücüden başlatıldı; dondurulamadı: {e}"),
        };
        let key = format!("usbrun:{}", exe.to_ascii_lowercase());
        let now = now_ms();
        crate::watchers::set_finding(
            shared,
            Some(Finding {
                key: key.clone(),
                entity_kind: "process".into(),
                entity: exe.clone(),
                title: format!("USB sürücüden çalışan program: {}", p.name),
                severity: sev,
                score: 55,
                signals: vec![Signal {
                    rule: "usb.exec".into(),
                    label: if res.is_ok() { "Çıkarılabilir sürücüden başlatıldı, USB kalkanı dondurdu".into() } else { "Çıkarılabilir sürücüden başlatıldı".into() },
                    weight: 55,
                    evidence: exe.clone(),
                }],
                first_seen: now,
                last_seen: now,
                pid: Some(p.pid),
                pids: vec![p.pid],
                status: "open".into(),
            }),
            &key,
        );
        emit_event(
            app,
            shared,
            event("usb.exec", sev, title, detail, Some(exe.clone()), json!({ "key": key, "pid": p.pid, "pids": [p.pid], "exe": exe, "frozen": res.is_ok() })),
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn root_parsing() {
        assert_eq!(super::root_of(r"e:\tools\x.exe").as_deref(), Some(r"E:\"));
        assert_eq!(super::root_of(r"\\server\share\x.exe"), None);
    }
}
