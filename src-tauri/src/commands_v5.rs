//! IPC for 0.5: incident response context, user rules, DNS history, process time machine,
//! weekly diff.

use std::collections::HashMap;
use std::sync::Arc;

use rusqlite::params;
use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, State};

use crate::engine::user_rules::{self, UserRule};
use crate::guard::{dnslog, firewall};
use crate::history::{self, ProcRun};
use crate::model::{Finding, Severity};
use crate::monitor::{emit_event, event};
use crate::state::Shared;

type S<'a> = State<'a, Arc<Shared>>;
type R<T> = Result<T, String>;

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

// ---------------------------------------------------------------- incident response

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningRef {
    pub pid: u32,
    pub name: String,
    pub critical: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupRef {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub location: String,
    pub command: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteRef {
    pub remote: String,
    pub port: u16,
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub last: i64,
    pub count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRef {
    pub name: String,
    pub last: i64,
    pub count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentContext {
    pub key: String,
    /// Executable / file behind the finding, when it is a path.
    pub path: Option<String>,
    pub file_exists: bool,
    pub running: Vec<RunningRef>,
    /// Firewall rule that already blocks this program.
    pub blocked_by: Option<String>,
    pub quarantined: bool,
    pub startup: Vec<StartupRef>,
    pub remotes: Vec<RemoteRef>,
    pub dns: Vec<DnsRef>,
    /// The latest recorded run first, then its parents (nearest first).
    pub lineage: Vec<ProcRun>,
    pub runs: i64,
    pub first_run: Option<i64>,
}

fn find_finding(s: &Shared, key: &str) -> Option<Finding> {
    if let Some(f) = s.findings.read().iter().find(|f| f.key == key) {
        return Some(f.clone());
    }
    s.store.lock().finding_history(5000).ok()?.into_iter().find(|f| f.key == key)
}

#[tauri::command]
pub fn incident_context(s: S, key: String) -> R<IncidentContext> {
    let f = find_finding(&s, &key).ok_or("Bulgu bulunamadı")?;
    let path = std::path::Path::new(&f.entity).is_absolute().then(|| f.entity.clone());
    let lower = path.as_deref().map(str::to_ascii_lowercase);

    let running: Vec<RunningRef> = s
        .processes
        .read()
        .iter()
        .filter(|p| {
            f.pids.contains(&p.pid) || (lower.is_some() && p.exe.as_deref().map(str::to_ascii_lowercase) == lower)
        })
        .map(|p| RunningRef { pid: p.pid, name: p.name.clone(), critical: p.critical })
        .collect();

    let blocked_by = lower.as_ref().and_then(|l| {
        firewall::rules(&s).into_iter().find(|r| r.kind == "program" && r.target.to_ascii_lowercase() == *l).map(|r| r.name)
    });

    let startup: Vec<StartupRef> = match &lower {
        Some(l) => s
            .startup
            .read()
            .iter()
            .filter(|it| {
                it.image.as_deref().map(str::to_ascii_lowercase).as_deref() == Some(l.as_str())
                    || it.command.to_ascii_lowercase().contains(l.as_str())
            })
            .map(|it| StartupRef {
                id: it.id.clone(),
                kind: it.kind.clone(),
                name: it.name.clone(),
                location: it.location.clone(),
                command: it.command.clone(),
            })
            .collect(),
        None => vec![],
    };

    let st = s.store.lock();
    let db = &st.conn;
    let (mut remotes, mut dns, mut lineage, mut runs, mut first_run, mut quarantined) = (vec![], vec![], vec![], 0, None, false);
    if let Some(p) = &path {
        let week = now() - 7 * 24 * 3600 * 1000;
        if let Ok(mut q) = db.prepare(
            "SELECT remote, port, hostname, country, MAX(ts), COUNT(*) FROM conn_history
              WHERE exe = ?1 COLLATE NOCASE AND ts >= ?2 GROUP BY remote ORDER BY MAX(ts) DESC LIMIT 25",
        ) {
            remotes = q
                .query_map(params![p, week], |r| {
                    Ok(RemoteRef {
                        remote: r.get(0)?,
                        port: r.get::<_, i64>(1)? as u16,
                        hostname: r.get(2)?,
                        country: r.get(3)?,
                        last: r.get(4)?,
                        count: r.get(5)?,
                    })
                })
                .map(|it| it.flatten().collect())
                .unwrap_or_default();
        }
        if let Ok(mut q) = db.prepare(
            "SELECT name, MAX(ts), COUNT(*) FROM dns_log WHERE exe = ?1 COLLATE NOCASE AND ts >= ?2
              GROUP BY name ORDER BY MAX(ts) DESC LIMIT 25",
        ) {
            dns = q
                .query_map(params![p, week], |r| Ok(DnsRef { name: r.get(0)?, last: r.get(1)?, count: r.get(2)? }))
                .map(|it| it.flatten().collect())
                .unwrap_or_default();
        }
        if let Some(run) = history::latest_run_of(db, p) {
            let parents = history::lineage(db, run.pid, run.started, 8);
            lineage.push(run);
            lineage.extend(parents);
        }
        (runs, first_run) = db
            .query_row("SELECT COUNT(*), MIN(started) FROM proc_history WHERE exe = ?1 COLLATE NOCASE", [p], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap_or((0, None));
        quarantined = db
            .query_row("SELECT EXISTS(SELECT 1 FROM quarantine WHERE original = ?1 COLLATE NOCASE)", [p], |r| r.get(0))
            .unwrap_or(false);
    }
    drop(st);

    Ok(IncidentContext {
        key,
        file_exists: path.as_deref().is_some_and(|p| std::path::Path::new(p).exists()),
        path,
        running,
        blocked_by,
        quarantined,
        startup,
        remotes,
        dns,
        lineage,
        runs,
        first_run,
    })
}

// ---------------------------------------------------------------- user rules

#[tauri::command]
pub fn user_rules_get(s: S) -> Vec<UserRule> {
    s.user_rules.read().clone()
}

#[tauri::command]
pub fn user_rules_save(app: AppHandle, s: S, rules: Vec<UserRule>) -> R<()> {
    user_rules::save(&s.store.lock(), &rules)?;
    let n = rules.len();
    *s.user_rules.write() = rules;
    emit_event(
        &app,
        &s,
        event("user.rules", Severity::Info, format!("Kendi kurallarınız güncellendi ({n} kural)"), String::new(), None, json!({ "count": n })),
    );
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleMatch {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub evidence: String,
}

/// Try a rule against the processes running now, without saving it.
#[tauri::command]
pub fn user_rule_test(s: S, rule: UserRule) -> R<Vec<RuleMatch>> {
    rule.validate()?;
    let procs = s.processes.read();
    let conns = s.connections.read();
    let names: HashMap<u32, &str> = procs.iter().map(|p| (p.pid, p.name.as_str())).collect();
    let mut by_pid: HashMap<u32, Vec<&crate::model::ConnectionInfo>> = HashMap::new();
    for c in conns.iter() {
        by_pid.entry(c.pid).or_default().push(c);
    }
    Ok(procs
        .iter()
        .filter(|p| p.pid > 4)
        .filter_map(|p| {
            let parent = p.ppid.and_then(|pp| names.get(&pp).copied());
            let cs = by_pid.get(&p.pid).map(|v| v.as_slice()).unwrap_or(&[]);
            rule.matches(p, parent, cs).map(|evidence| RuleMatch { pid: p.pid, name: p.name.clone(), exe: p.exe.clone(), evidence })
        })
        .take(200)
        .collect())
}

// ---------------------------------------------------------------- DNS

#[tauri::command]
pub fn dns_status(s: S) -> dnslog::DnsStatus {
    s.dns.read().clone()
}

#[tauri::command]
pub fn dns_log(s: S, search: Option<String>, exe: Option<String>, since: Option<i64>, limit: Option<u32>) -> R<Vec<dnslog::DnsRow>> {
    dnslog::query(&s.store.lock().conn, search.as_deref(), exe.as_deref(), since, limit.unwrap_or(500).min(5000)).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- process time machine

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcAt {
    pub ts: i64,
    pub earliest: Option<i64>,
    pub runs: Vec<ProcRun>,
}

#[tauri::command]
pub fn proc_at(s: S, ts: i64) -> R<ProcAt> {
    let st = s.store.lock();
    let since = st.setting(history::SINCE_KEY).ok().flatten().and_then(|v| v.parse().ok());
    Ok(ProcAt {
        ts,
        earliest: since.or_else(|| history::earliest(&st.conn)),
        runs: history::at(&st.conn, ts).map_err(|e| e.to_string())?,
    })
}

#[tauri::command]
pub fn proc_changes(s: S, since: i64, until: i64, limit: Option<u32>) -> R<Vec<ProcRun>> {
    history::changes(&s.store.lock().conn, since, until, limit.unwrap_or(300).min(3000)).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn proc_lineage(s: S, pid: u32, started: i64) -> Vec<ProcRun> {
    history::lineage(&s.store.lock().conn, pid, started, 10)
}

// ---------------------------------------------------------------- weekly diff

#[tauri::command]
pub fn weekly_diff(s: S) -> crate::weekly::WeeklyDiff {
    crate::weekly::build(&s.store.lock().conn, now())
}

// ---------------------------------------------------------------- 0.6: traces, phone summary

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Traces {
    pub remotes: Vec<RemoteRef>,
    pub dns: Vec<DnsRef>,
}

/// Network and DNS activity of one program between `since` and `until`.
#[tauri::command]
pub fn proc_traces(s: S, exe: String, since: i64, until: i64) -> R<Traces> {
    let st = s.store.lock();
    let db = &st.conn;
    let mut q = db
        .prepare(
            "SELECT remote, port, hostname, country, MAX(ts), COUNT(*) FROM conn_history
              WHERE exe = ?1 COLLATE NOCASE AND ts BETWEEN ?2 AND ?3 GROUP BY remote, port ORDER BY MIN(ts) LIMIT 100",
        )
        .map_err(|e| e.to_string())?;
    let remotes = q
        .query_map(params![exe, since, until], |r| {
            Ok(RemoteRef { remote: r.get(0)?, port: r.get::<_, i64>(1)? as u16, hostname: r.get(2)?, country: r.get(3)?, last: r.get(4)?, count: r.get(5)? })
        })
        .map_err(|e| e.to_string())?
        .flatten()
        .collect();
    let mut q = db
        .prepare(
            "SELECT name, MAX(ts), COUNT(*) FROM dns_log WHERE exe = ?1 COLLATE NOCASE AND ts BETWEEN ?2 AND ?3
              AND name NOT LIKE '%.arpa' GROUP BY name ORDER BY MIN(ts) LIMIT 100",
        )
        .map_err(|e| e.to_string())?;
    let dns = q
        .query_map(params![exe, since, until], |r| Ok(DnsRef { name: r.get(0)?, last: r.get(1)?, count: r.get(2)? }))
        .map_err(|e| e.to_string())?
        .flatten()
        .collect();
    Ok(Traces { remotes, dns })
}

/// Send the weekly summary to the phone now (button in settings).
#[tauri::command]
pub async fn remote_weekly_now(s: State<'_, Arc<Shared>>) -> R<String> {
    let shared = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let text = crate::guard::remotecmd::weekly_text(&shared);
        crate::guard::remote::send_text(&shared, &text).map(|_| text)
    })
    .await
    .map_err(|e| e.to_string())?
}
