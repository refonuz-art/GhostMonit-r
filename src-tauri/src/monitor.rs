//! Background monitoring loop: collects, diffs, runs the engine, persists, emits.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use sysinfo::{System, Users};
use tauri::{AppHandle, Emitter};

use crate::collectors::{network::NetworkCollector, process, system::SystemCollector};
use crate::engine::{Engine, EngineInput};
use crate::model::{AddrScope, Finding, SecurityEvent, Severity};
use crate::state::Shared;

/// First-run learning window: listening ports seen during it become the baseline.
const LEARNING_MS: i64 = 3 * 60 * 1000;

pub fn emit_event(app: &AppHandle, shared: &Shared, mut e: SecurityEvent) {
    if let Ok(id) = shared.store.lock().insert_event(&e) {
        e.id = id;
    }
    crate::shell::maybe_notify(app, shared, &e);
    crate::guard::remote::maybe_send(app, shared, &e);
    let _ = app.emit("gm://event", &e);
}

pub fn event(kind: &str, sev: Severity, title: String, detail: String, subject: Option<String>, data: serde_json::Value) -> SecurityEvent {
    SecurityEvent {
        id: 0,
        ts: chrono::Utc::now().timestamp_millis(),
        kind: kind.into(),
        severity: sev,
        title,
        detail,
        subject,
        data,
    }
}

pub fn spawn(app: AppHandle, shared: Arc<Shared>) {
    std::thread::Builder::new()
        .name("monitor".into())
        .spawn(move || run(app, shared))
        .expect("spawn monitor");
}

fn run(app: AppHandle, shared: Arc<Shared>) {
    let (Ok(mut sys), Ok(mut users), Ok(mut syscol)) =
        (System::new(), Users::new_with_refreshed_list(), SystemCollector::new())
    else {
        log::error!("sysinfo init failed; monitor not started");
        return;
    };
    let mut netcol = NetworkCollector::default();
    let mut engine = Engine::default();

    // Learning window bookkeeping persisted in settings.
    let learning_until: i64 = {
        let st = shared.store.lock();
        match st.setting("baseline_learning_until").ok().flatten().and_then(|v| v.parse().ok()) {
            Some(v) => v,
            None => {
                let v = chrono::Utc::now().timestamp_millis() + LEARNING_MS;
                let _ = st.set_setting("baseline_learning_until", &v.to_string());
                v
            }
        }
    };
    let mut listen_baseline: HashSet<String> =
        shared.store.lock().baseline("listen").unwrap_or_default().into_iter().collect();
    let mut known_remotes: HashSet<String> = HashSet::new();
    // Findings already recorded in earlier sessions don't re-announce themselves.
    let mut known_findings: HashMap<String, Severity> = shared
        .store
        .lock()
        .finding_history(5000)
        .unwrap_or_default()
        .into_iter()
        .map(|f| (f.key, f.severity))
        .collect();
    let mut prev_pids: Option<HashSet<u32>> = None;
    let mut proc_tracker = crate::history::ProcTracker::default();
    let mut hashdb_size: i64 = 0;
    let mut bad_checked: HashMap<String, Option<String>> = HashMap::new();

    sys.refresh_cpu_usage();
    process::refresh(&mut sys);
    std::thread::sleep(Duration::from_millis(400));

    let self_exe = std::env::current_exe().ok().map(|p| p.to_string_lossy().into_owned());
    let mut tick: u64 = 0;
    let mut last_prune = Instant::now() - Duration::from_secs(3600);
    loop {
        let started = Instant::now();
        let bg = shared.background.load(Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp_millis();

        sys.refresh_cpu_usage();
        sys.refresh_memory();

        let heavy = tick % 2 == 0;
        if heavy {
            process::refresh(&mut sys);
            if tick % 60 == 0 {
                users.refresh();
                shared.sigs.revalidate();
            }
            let names: HashMap<u32, String> =
                sys.processes().values().map(|p| (p.pid().as_u32(), p.name().to_string_lossy().into_owned())).collect();
            let mut conns = netcol.collect(&names);
            for c in conns.iter_mut() {
                if c.scope != AddrScope::Public {
                    continue;
                }
                if let Some(ip) = c.remote_addr.as_deref().and_then(|r| r.parse::<std::net::IpAddr>().ok()) {
                    c.hostname = shared.rdns.get(ip);
                    let g = shared.geo.lookup(ip);
                    c.country = g.country;
                    c.asn = g.asn;
                }
            }
            let mut counts: HashMap<u32, u32> = HashMap::new();
            for c in &conns {
                if c.remote_addr.is_some() {
                    *counts.entry(c.pid).or_default() += 1;
                }
            }
            let mut procs = process::collect(&sys, &users, &shared.sigs, &counts);

            // ---- process time machine ----
            {
                let st = shared.store.lock();
                if prev_pids.is_none() {
                    crate::history::close_stale(&st.conn, &crate::history::live_keys(&procs), now);
                    if st.setting(crate::history::SINCE_KEY).ok().flatten().is_none() {
                        let _ = st.set_setting(crate::history::SINCE_KEY, &now.to_string());
                    }
                }
                proc_tracker.update(&st.conn, &procs, now);
            }

            // ---- process start events ----
            let pids: HashSet<u32> = procs.iter().map(|p| p.pid).collect();
            if let Some(prev) = &prev_pids {
                let fresh: Vec<&crate::model::ProcessInfo> = procs.iter().filter(|p| !prev.contains(&p.pid)).collect();
                // The shared list still holds the previous tick; the shield needs these pids.
                if !fresh.is_empty() && shared.settings.read().usb_shield {
                    shared.processes.write().extend(fresh.iter().map(|p| (*p).clone()));
                    crate::guard::usbshield::check(&app, &shared, &fresh);
                }
                for p in procs.iter().filter(|p| !prev.contains(&p.pid)) {
                    emit_event(
                        &app,
                        &shared,
                        event(
                            "process.start",
                            Severity::Info,
                            format!("Yeni işlem başlatıldı: {}", p.name),
                            p.exe.clone().unwrap_or_default(),
                            Some(p.name.clone()),
                            json!({ "pid": p.pid, "ppid": p.ppid, "exe": p.exe, "cmd": p.cmd }),
                        ),
                    );
                }
            }
            prev_pids = Some(pids);

            // ---- new remote hosts ----
            let exe_of: HashMap<u32, Option<String>> = procs.iter().map(|p| (p.pid, p.exe.clone())).collect();
            for c in conns.iter().filter(|c| c.scope == AddrScope::Public && c.state == "ESTABLISHED") {
                let Some(remote) = &c.remote_addr else { continue };
                let exe = exe_of.get(&c.pid).cloned().flatten();
                let key = format!("{}|{}", exe.as_deref().unwrap_or("?"), remote);
                if known_remotes.insert(key) {
                    let st = shared.store.lock();
                    let seen_before: bool = st
                        .conn
                        .query_row("SELECT EXISTS(SELECT 1 FROM conn_history WHERE remote=?1)", [remote], |r| r.get(0))
                        .unwrap_or(false);
                    let _ = st.conn.execute(
                        "INSERT INTO conn_history (ts, pid, process, exe, protocol, remote, port, hostname, country, asn)
                         VALUES (?1,?2,?3,?4,'TCP',?5,?6,?7,?8,?9)",
                        rusqlite::params![
                            now, c.pid, c.process_name, exe, remote, c.remote_port.unwrap_or(0),
                            c.hostname, c.country, c.asn
                        ],
                    );
                    drop(st);
                    if !seen_before {
                        emit_event(
                            &app,
                            &shared,
                            event(
                                "network.new_remote",
                                Severity::Info,
                                format!("Yeni uzak adresle bağlantı: {}", remote),
                                format!(
                                    "{} → {}:{}",
                                    c.process_name.as_deref().unwrap_or("?"),
                                    remote,
                                    c.remote_port.unwrap_or(0)
                                ),
                                c.process_name.clone(),
                                json!({ "pid": c.pid, "remote": remote, "port": c.remote_port, "exe": exe }),
                            ),
                        );
                    }
                }
            }

            // ---- engine ----
            let learning = now < learning_until;
            let trusted: HashSet<String> = shared.store.lock().trusted().unwrap_or_default().into_iter().collect();
            if tick % 10 == 0 {
                let n = crate::intel::hashdb::stats(&shared.store.lock().conn).map(|s| s.total).unwrap_or(0);
                if n != hashdb_size {
                    bad_checked.clear();
                    hashdb_size = n;
                }
            }
            let mut bad_hash_hits: HashMap<String, String> = HashMap::new();
            if hashdb_size > 0 {
                for p in &procs {
                    let Some(exe) = &p.exe else { continue };
                    let k = exe.to_ascii_lowercase();
                    if let Some(hit) = bad_checked.get(&k) {
                        if let Some(n) = hit {
                            bad_hash_hits.insert(k, n.clone());
                        }
                        continue;
                    }
                    if let Some(h) = shared.exe_hashes.get_or_queue(exe) {
                        let hit = crate::intel::hashdb::lookup(&shared.store.lock().conn, &h);
                        if let Some(n) = &hit {
                            bad_hash_hits.insert(k.clone(), n.clone());
                        }
                        bad_checked.insert(k, hit);
                    }
                }
            }
            let user_rules = shared.user_rules.read().clone();
            let out = engine.evaluate(&EngineInput {
                processes: &procs,
                connections: &conns,
                listen_baseline: &listen_baseline,
                learning,
                trusted: &trusted,
                bad_hash_hits: &bad_hash_hits,
                user_rules: &user_rules,
                now,
            });
            if !out.learned_ports.is_empty() {
                let st = shared.store.lock();
                for k in out.learned_ports {
                    if listen_baseline.insert(k.clone()) {
                        let _ = st.add_baseline("listen", &k);
                    }
                }
            }
            let mut all = out.findings;
            all.extend(shared.startup_findings.read().iter().cloned());
            all.extend(shared.watch_findings.read().iter().cloned());
            // Ghost Monitor itself is unsigned and lives in AppData; it is not a finding.
            if let Some(me) = &self_exe {
                all.retain(|f| !f.entity.eq_ignore_ascii_case(me));
            }
            // Stable order: most severe first, then newest, so rows don't jump between ticks.
            all.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.score.cmp(&a.score)).then(a.key.cmp(&b.key)));
            let findings = persist_findings(&app, &shared, all, &mut known_findings);

            // annotate risk on processes and connections
            let mut risk: HashMap<u32, Severity> = HashMap::new();
            for f in &findings {
                for pid in &f.pids {
                    let e = risk.entry(*pid).or_insert(f.severity);
                    *e = (*e).max(f.severity);
                }
            }
            for p in procs.iter_mut() {
                p.risk = risk.get(&p.pid).copied();
            }
            for c in conns.iter_mut() {
                c.risk = risk.get(&c.pid).copied();
            }

            let _ = app.emit("gm://processes", &procs);
            let _ = app.emit("gm://connections", &conns);
            let open: Vec<&Finding> = findings.iter().filter(|f| f.severity > Severity::Info).collect();
            crate::shell::update_tray(&app, open.len(), open.iter().map(|f| f.severity).max());
            let _ = app.emit("gm://findings", &findings);
            *shared.processes.write() = procs;
            *shared.connections.write() = conns;
            *shared.findings.write() = findings;
        }

        let pc = shared.processes.read().len();
        let m = syscol.collect(&sys, pc);
        let _ = app.emit("gm://metrics", &m);
        *shared.metrics.write() = Some(m);

        if last_prune.elapsed() > Duration::from_secs(3600) {
            let days = shared.settings.read().retention_days as i64;
            let _ = shared.store.lock().prune_events(now - days * 24 * 3600 * 1000);
            last_prune = Instant::now();
        }

        tick += 1;
        let period = if bg { Duration::from_millis(4000) } else { Duration::from_millis(1000) };
        if let Some(rest) = period.checked_sub(started.elapsed()) {
            std::thread::sleep(rest);
        }
    }
}

/// Persist findings, emit timeline events for new or escalated ones, drop dismissed ones.
fn persist_findings(
    app: &AppHandle,
    shared: &Shared,
    findings: Vec<Finding>,
    known: &mut HashMap<String, Severity>,
) -> Vec<Finding> {
    let mut out = Vec::with_capacity(findings.len());
    let mut new_events = Vec::new();
    {
        let st = shared.store.lock();
        for mut f in findings {
            if let Ok(Some((first, status))) = st.finding_first_seen(&f.key) {
                f.first_seen = first;
                if status == "dismissed" {
                    continue;
                }
            }
            let _ = st.upsert_finding(&f);
            let escalated = known.get(&f.key).map(|s| f.severity > *s).unwrap_or(true);
            known.insert(f.key.clone(), f.severity);
            if escalated && f.severity >= Severity::Low {
                new_events.push(event(
                    "threat.finding",
                    f.severity,
                    format!("Şüpheli davranış: {}", f.title),
                    f.signals.iter().map(|s| s.label.clone()).collect::<Vec<_>>().join(" · "),
                    Some(f.entity.clone()),
                    json!({ "key": f.key, "pid": f.pid, "pids": f.pids, "score": f.score }),
                ));
            }
            out.push(f);
        }
    }
    for e in new_events {
        emit_event(app, shared, e);
    }
    out
}
