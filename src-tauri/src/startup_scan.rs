//! Background autostart scanner: inventory → change history → findings.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tauri::{AppHandle, Emitter};

use crate::collectors::startup::{self, StartupItem};
use crate::engine::{rules, score};
use crate::model::{Finding, ProcessInfo, SecurityEvent, Severity, SignatureState};
use crate::store::Store;
use crate::monitor::{emit_event, event};
use crate::state::Shared;

pub fn spawn(app: AppHandle, shared: Arc<Shared>) -> Sender<()> {
    let (tx, rx) = channel::<()>();
    std::thread::Builder::new()
        .name("startup-scan".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(4));
            loop {
                run_once(&app, &shared);
                let period = Duration::from_secs(shared.settings.read().startup_scan_minutes as u64 * 60);
                match rx.recv_timeout(period) {
                    Ok(()) | Err(RecvTimeoutError::Timeout) => {
                        while rx.try_recv().is_ok() {} // coalesce bursts
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .expect("spawn startup scanner");
    tx
}

fn run_once(app: &AppHandle, shared: &Shared) {
    let now = chrono::Utc::now().timestamp_millis();
    let mut items = startup::scan();

    for it in items.iter_mut() {
        if let (Some(img), true) = (&it.image, it.image_exists) {
            it.signature = Some(shared.sigs.verify_now(img));
        }
    }

    let elevated = shared.host.read().elevated;
    let (events, fresh) = reconcile(&shared.store.lock(), &mut items, now, elevated);

    // ---- findings ----
    let trusted: HashSet<String> = shared.store.lock().trusted().unwrap_or_default().into_iter().collect();
    let me = std::env::current_exe().ok().map(|p| p.to_string_lossy().to_ascii_lowercase());
    let mut findings = Vec::new();
    for it in items.iter_mut() {
        let key = format!("startup:{}", it.id);
        if trusted.contains(&key) {
            continue;
        }
        // Our own autostart entry (Settings → start with Windows) is not a finding.
        if me.is_some() && it.image.as_ref().map(|i| i.to_ascii_lowercase()) == me {
            continue;
        }
        if let Some(f) = evaluate(it, fresh.contains(&it.id), now, key) {
            it.risk = Some(f.severity);
            findings.push(f);
        }
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.score.cmp(&a.score)));

    for e in events {
        emit_event(app, shared, e);
    }
    *shared.startup.write() = items.clone();
    *shared.startup_findings.write() = findings;
    *shared.startup_scanned_at.write() = Some(now);
    let _ = app.emit("gm://startup", &items);
}

const FRESH_WINDOW_MS: i64 = 24 * 3_600_000;
const BASELINE_USER: &str = "startup_scanned";
const BASELINE_ADMIN: &str = "startup_scanned_admin";

struct Known {
    command: String,
    first_seen: i64,
    removed_at: Option<i64>,
    admin_only: bool,
}

/// Persist the inventory, emit change events and return ids that count as new/changed.
///
/// Visibility depends on privilege: an elevated scan sees system tasks/services that a
/// standard-user scan cannot read. So:
/// - each privilege level has its own baseline; its first scan never reports "new";
/// - entries only ever seen elevated are not "removed" when a standard scan misses them;
/// - a service command that is unreadable in this scan (empty) is not a "change".
pub fn reconcile(
    st: &Store,
    items: &mut [StartupItem],
    now: i64,
    elevated: bool,
) -> (Vec<SecurityEvent>, HashSet<String>) {
    let mut events = Vec::new();
    let mut fresh: HashSet<String> = HashSet::new();
    let get = |k: &str| -> Option<i64> { st.setting(k).ok().flatten().and_then(|v| v.parse().ok()) };
    let base_user = get(BASELINE_USER);
    let base_admin = get(BASELINE_ADMIN);
    let my_base = if elevated { base_admin } else { base_user };
    let base_of = |admin_only: bool| if admin_only { base_admin } else { base_user.or(base_admin) };

    let mut known: HashMap<String, Known> = HashMap::new();
    if let Ok(mut stmt) = st.conn.prepare("SELECT id, command, first_seen, removed_at, scope FROM startup_items") {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                Known {
                    command: r.get(1)?,
                    first_seen: r.get(2)?,
                    removed_at: r.get(3)?,
                    admin_only: r.get::<_, String>(4)? == "admin",
                },
            ))
        }) {
            known.extend(rows.flatten());
        }
    }

    let tx = st.conn.unchecked_transaction();
    for it in items.iter_mut() {
        match known.get(&it.id) {
            None => {
                it.first_seen = now;
                let _ = st.conn.execute(
                    "INSERT INTO startup_items (id, kind, name, command, location, first_seen, last_seen, scope)
                     VALUES (?1,?2,?3,?4,?5,?6,?6,?7)",
                    rusqlite::params![it.id, it.kind, it.name, it.command, it.location, now, if elevated { "admin" } else { "user" }],
                );
                if my_base.is_some() {
                    fresh.insert(it.id.clone());
                    events.push(event(
                        "startup.new",
                        Severity::Low,
                        format!("Yeni başlangıç girdisi: {}", it.name),
                        it.command.clone(),
                        Some(it.name.clone()),
                        json!({ "id": it.id, "kind": it.kind, "location": it.location }),
                    ));
                }
            }
            Some(k) => {
                it.first_seen = k.first_seen;
                if !elevated && k.admin_only {
                    // A standard scan can read it after all: it is a user-visible entry.
                    let _ = st.conn.execute("UPDATE startup_items SET scope='user' WHERE id=?1", [&it.id]);
                }
                if base_of(k.admin_only).is_some_and(|b| k.first_seen > b) && now - k.first_seen < FRESH_WINDOW_MS {
                    fresh.insert(it.id.clone());
                }
                if it.command.is_empty() && !k.command.is_empty() {
                    it.command = k.command.clone(); // unreadable at this privilege, not changed
                }
                if k.command != it.command || k.removed_at.is_some() {
                    let _ = st.conn.execute(
                        "UPDATE startup_items SET command=?2, last_seen=?3, removed_at=NULL WHERE id=?1",
                        rusqlite::params![it.id, it.command, now],
                    );
                    fresh.insert(it.id.clone());
                    let (title, detail) = if k.command == it.command {
                        (format!("Başlangıç girdisi geri geldi: {}", it.name), it.command.clone())
                    } else {
                        (format!("Başlangıç girdisi değişti: {}", it.name), format!("önce: {}\nşimdi: {}", k.command, it.command))
                    };
                    events.push(event(
                        "startup.changed",
                        Severity::Low,
                        title,
                        detail,
                        Some(it.name.clone()),
                        json!({ "id": it.id, "before": k.command, "after": it.command }),
                    ));
                } else {
                    let _ = st.conn.execute("UPDATE startup_items SET last_seen=?2 WHERE id=?1", rusqlite::params![it.id, now]);
                }
            }
        }
    }

    let present: HashSet<&str> = items.iter().map(|i| i.id.as_str()).collect();
    for (id, k) in &known {
        if k.removed_at.is_some() || present.contains(id.as_str()) {
            continue;
        }
        if !elevated && k.admin_only {
            continue; // out of view at this privilege level, not deleted
        }
        let _ = st.conn.execute("UPDATE startup_items SET removed_at=?2 WHERE id=?1", rusqlite::params![id, now]);
        let name: String = st
            .conn
            .query_row("SELECT name FROM startup_items WHERE id=?1", [id], |r| r.get(0))
            .unwrap_or_else(|_| id.rsplit('|').next().unwrap_or(id).to_string());
        events.push(event(
            "startup.removed",
            Severity::Info,
            format!("Başlangıç girdisi kaldırıldı: {name}"),
            k.command.clone(),
            Some(name),
            json!({ "id": id }),
        ));
    }
    if let Ok(tx) = tx {
        let _ = tx.commit();
    }
    if my_base.is_none() {
        let _ = st.set_setting(if elevated { BASELINE_ADMIN } else { BASELINE_USER }, &now.to_string());
    }
    (events, fresh)
}

/// Same rule set and scoring as running processes, plus autostart-specific signals.
pub fn evaluate(it: &StartupItem, fresh: bool, now: i64, key: String) -> Option<Finding> {
    let name = it
        .image
        .as_deref()
        .and_then(|p| p.rsplit('\\').next())
        .unwrap_or(&it.name)
        .to_string();
    let as_proc = ProcessInfo {
        pid: 0,
        ppid: None,
        name,
        exe: it.image.clone().filter(|_| it.image_exists),
        cmd: Some(it.command.clone()),
        cpu: 0.0,
        memory: 0,
        start_time: 0,
        user: None,
        signature: it.signature.clone().unwrap_or(crate::model::SignatureInfo {
            state: SignatureState::Unknown,
            publisher: None,
        }),
        connections: 0,
        critical: false,
        risk: None,
    };
    let mut s = Vec::new();
    s.extend(rules::masquerade(&as_proc));
    s.extend(rules::signature_and_location(&as_proc));
    s.extend(rules::command_line(&as_proc));
    if it.kind == "winlogon" {
        s.push(rules::sig("startup.winlogon", "Winlogon kaydı Windows varsayılanından farklı", 45, it.command.clone()));
    }
    if it.image.is_some() && !it.image_exists && it.enabled {
        s.push(rules::sig("startup.missing", "Başlangıç hedefi diskte bulunamadı", 10, it.image.clone().unwrap_or_default()));
    }
    if fresh {
        s.push(rules::sig("startup.new", "Yeni veya değişmiş otomatik başlatma kaydı", 10, it.location.clone()));
    }
    if s.is_empty() || s.iter().all(|x| x.rule == "sig.unsigned") {
        return None;
    }
    let (total, severity) = score(&s);
    if severity == Severity::Info {
        return None;
    }
    let title = s.iter().max_by_key(|x| x.weight).map(|x| x.label.clone()).unwrap_or_default();
    Some(Finding {
        key,
        entity_kind: "startup".into(),
        entity: format!("{} — {}", it.name, it.image.clone().unwrap_or_else(|| it.command.clone())),
        title,
        severity,
        score: total,
        signals: s,
        first_seen: now,
        last_seen: now,
        pid: None,
        pids: vec![],
        status: "open".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SignatureInfo;

    fn it(kind: &str, cmd: &str, sig: SignatureState) -> StartupItem {
        let mut i = StartupItem {
            id: "x".into(),
            kind: kind.into(),
            name: "x".into(),
            command: cmd.into(),
            location: "loc".into(),
            image: startup::image_of(cmd),
            image_exists: true,
            enabled: true,
            start: None,
            state: None,
            account: None,
            author: None,
            signature: Some(SignatureInfo { state: sig, publisher: None }),
            first_seen: 0,
            risk: None,
        };
        i.image_exists = true;
        i
    }

    fn named(id: &str, cmd: &str) -> StartupItem {
        let mut i = it("registry", cmd, SignatureState::Signed);
        i.id = id.into();
        i.name = id.to_uppercase();
        i
    }

    fn kinds(ev: &[SecurityEvent]) -> Vec<&str> {
        let mut k: Vec<&str> = ev.iter().map(|e| e.kind.as_str()).collect();
        k.sort();
        k
    }

    #[test]
    fn reconcile_lifecycle() {
        let st = Store::open_memory().unwrap();
        let h = 3_600_000;

        // 1) baseline: nothing is "new"
        let mut scan = vec![named("a", "a.exe"), named("b", "b.exe")];
        let (ev, fresh) = reconcile(&st, &mut scan, 1_000, false);
        assert!(ev.is_empty() && fresh.is_empty());

        // 2) unchanged rescan: silent
        let mut scan = vec![named("a", "a.exe"), named("b", "b.exe")];
        let (ev, _) = reconcile(&st, &mut scan, 1_000 + h, false);
        assert!(ev.is_empty());

        // 3) one added, one changed, one removed
        let mut scan = vec![named("a", "a.exe --evil"), named("c", "c.exe")];
        let (ev, fresh) = reconcile(&st, &mut scan, 1_000 + 2 * h, false);
        assert_eq!(kinds(&ev), ["startup.changed", "startup.new", "startup.removed"]);
        assert!(fresh.contains("a") && fresh.contains("c"));
        let removed = ev.iter().find(|e| e.kind == "startup.removed").unwrap();
        assert_eq!(removed.subject.as_deref(), Some("B"), "removed entry keeps its display name");

        // 4) a new entry stays "fresh" for 24 h, then it is ordinary
        let mut scan = vec![named("a", "a.exe --evil"), named("c", "c.exe")];
        let (ev, fresh) = reconcile(&st, &mut scan, 1_000 + 3 * h, false);
        assert!(ev.is_empty());
        assert!(fresh.contains("c") && !fresh.contains("a"));
        let mut scan = vec![named("a", "a.exe --evil"), named("c", "c.exe")];
        let (_, fresh) = reconcile(&st, &mut scan, 1_000 + 27 * h, false);
        assert!(fresh.is_empty());

        // 5) a removed entry that comes back is reported once
        let mut scan = vec![named("a", "a.exe --evil"), named("b", "b.exe"), named("c", "c.exe")];
        let (ev, _) = reconcile(&st, &mut scan, 1_000 + 28 * h, false);
        assert_eq!(kinds(&ev), ["startup.changed"]);
        assert!(ev[0].title.contains("geri geldi"));
    }

    /// Reproduces 2026-11-16: an elevated run saw 35 system tasks ("new"), the next
    /// standard run could not read them ("removed"). Neither should be reported.
    #[test]
    fn privilege_flicker_is_not_a_change() {
        let st = Store::open_memory().unwrap();
        let h = 3_600_000;
        let user_view = || vec![named("a", "a.exe"), named("svc", "")];
        let admin_view = || {
            let mut v = vec![named("a", "a.exe"), named("svc", r"C:\Windows\svc.exe"), named("sys1", "x.exe"), named("sys2", "y.exe")];
            v.iter_mut().for_each(|i| i.kind = "task".into());
            v
        };

        assert!(reconcile(&st, &mut user_view(), 0, false).0.is_empty(), "user baseline");
        let (ev, _) = reconcile(&st, &mut admin_view(), h, true);
        // The first elevated scan is the baseline for admin-only entries: no "new" for sys1/sys2.
        assert!(!ev.iter().any(|e| e.kind == "startup.new"), "{:?}", kinds(&ev));

        // Back to standard user: admin-only entries are out of view, svc command unreadable.
        let (ev, _) = reconcile(&st, &mut user_view(), 2 * h, false);
        assert!(ev.is_empty(), "flicker reported: {:?}", kinds(&ev));
        let (ev, _) = reconcile(&st, &mut admin_view(), 3 * h, true);
        assert!(ev.is_empty(), "flicker reported on re-elevation: {:?}", kinds(&ev));

        // A genuine deletion seen by an elevated scan is still reported.
        let mut v = admin_view();
        v.retain(|i| i.id != "sys2");
        let (ev, _) = reconcile(&st, &mut v, 4 * h, true);
        assert_eq!(kinds(&ev), ["startup.removed"]);

        // A genuinely new entry after both baselines is reported.
        let mut v = admin_view();
        v.retain(|i| i.id != "sys2");
        v.push(named("evil", r"C:\Users\Public\evil.exe"));
        let (ev, _) = reconcile(&st, &mut v, 5 * h, true);
        assert_eq!(kinds(&ev), ["startup.new"]);
    }

    #[test]
    fn migration_v2_repairs_flicker_rows() {
        let st = Store::open_memory().unwrap();
        // Simulate v1 state: roll back to v1 and replay the bad rows.
        st.conn
            .execute_batch(
                "DROP TABLE startup_items;
                 DROP TABLE quarantine;
                 CREATE TABLE startup_items (id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,
                   command TEXT NOT NULL, location TEXT NOT NULL, first_seen INTEGER NOT NULL,
                   last_seen INTEGER NOT NULL, removed_at INTEGER);
                 INSERT INTO startup_items VALUES ('task|\\sys', 'task', 'sys', 'x.exe', '\\', 1000, 1000, 49000);
                 INSERT INTO startup_items VALUES ('registry|run|old', 'registry', 'old', 'o.exe', 'Run', 1000, 9000000, 9000001);
                 DELETE FROM settings;
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        st.migrate().unwrap();
        let row = |id: &str| -> (String, Option<i64>) {
            st.conn.query_row("SELECT scope, removed_at FROM startup_items WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
        };
        assert_eq!(row(r"task|\sys"), ("admin".into(), None), "flicker repaired");
        assert_eq!(row("registry|run|old"), ("user".into(), Some(9000001)), "real removal kept");
        assert_eq!(st.setting("startup_scanned_admin").unwrap().as_deref(), Some("1000"));
    }

    #[test]
    fn encoded_powershell_autorun_is_flagged() {
        let i = it(
            "registry",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -enc SQBFAFgA",
            SignatureState::Signed,
        );
        let f = evaluate(&i, true, 0, "k".into()).unwrap();
        assert!(f.severity >= Severity::Medium, "{:?}", f.severity);
    }

    #[test]
    fn signed_program_files_entry_is_quiet() {
        let i = it("registry", r#""C:\Program Files\Vendor\app.exe" --tray"#, SignatureState::Signed);
        assert!(evaluate(&i, false, 0, "k".into()).is_none());
    }

    #[test]
    fn unsigned_temp_autorun_is_flagged() {
        let i = it("registry", r"C:\Users\u\AppData\Local\Temp\upd.exe", SignatureState::Unsigned);
        assert!(evaluate(&i, false, 0, "k".into()).is_some());
    }
}
