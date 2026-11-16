//! Threat engine: runs rules per entity, correlates signals, assigns severity.
//!
//! Scoring policy (false-positive control):
//! - Severity comes from the summed weight of *distinct* rules.
//! - A single signal can never exceed MEDIUM unless it is a definitive indicator
//!   (known-bad hash, weight >= 100).
//! - CRITICAL requires at least two independent rules (or a definitive indicator).

pub mod rules;

use std::collections::{HashMap, HashSet};

use crate::model::{ConnectionInfo, Finding, ProcessInfo, Severity, Signal, SignatureState};

pub const DEFINITIVE_WEIGHT: u32 = 100;

pub fn score(signals: &[Signal]) -> (u32, Severity) {
    // De-duplicate by rule; keep the strongest signal per rule.
    let mut best: HashMap<&str, u32> = HashMap::new();
    for s in signals {
        let e = best.entry(s.rule.as_str()).or_insert(0);
        *e = (*e).max(s.weight);
    }
    let total: u32 = best.values().sum();
    let distinct = best.len();
    let definitive = best.values().any(|w| *w >= DEFINITIVE_WEIGHT);

    let mut sev = match total {
        0..=14 => Severity::Info,
        15..=29 => Severity::Low,
        30..=54 => Severity::Medium,
        55..=79 => Severity::High,
        _ => Severity::Critical,
    };
    if !definitive {
        if distinct <= 1 && sev > Severity::Medium {
            sev = Severity::Medium;
        }
        if distinct < 2 && sev == Severity::Critical {
            sev = Severity::High;
        }
    } else {
        sev = Severity::Critical;
    }
    (total, sev)
}

pub fn process_key(p: &ProcessInfo) -> String {
    format!("process:{}", p.exe.as_deref().unwrap_or(&p.name).to_ascii_lowercase())
}

/// Command-line based findings are keyed per command line, so trusting one PowerShell
/// invocation does not whitelist every PowerShell process.
fn cmdline_key(base: &str, cmd: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in cmd.trim().to_ascii_lowercase().bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{base}#{h:016x}")
}

pub struct EngineInput<'a> {
    pub processes: &'a [ProcessInfo],
    pub connections: &'a [ConnectionInfo],
    /// "proto:port:exe" strings considered normal.
    pub listen_baseline: &'a HashSet<String>,
    pub learning: bool,
    pub trusted: &'a HashSet<String>,
    pub bad_hash_hits: &'a HashMap<String, String>,
    pub now: i64,
}

pub struct EngineOutput {
    pub findings: Vec<Finding>,
    /// Listening sockets seen while learning → to be added to the baseline.
    pub learned_ports: Vec<String>,
}

#[derive(Default)]
pub struct Engine {
    high_cpu_since: HashMap<u32, i64>,
}

pub fn listen_key(c: &ConnectionInfo, exe: Option<&str>) -> String {
    format!(
        "{}:{}:{}",
        if matches!(c.protocol, crate::model::Protocol::Tcp) { "tcp" } else { "udp" },
        c.local_port,
        exe.unwrap_or("?").to_ascii_lowercase()
    )
}

impl Engine {
    pub fn evaluate(&mut self, inp: &EngineInput) -> EngineOutput {
        let names: HashMap<u32, &str> = inp.processes.iter().map(|p| (p.pid, p.name.as_str())).collect();
        let mut by_pid: HashMap<u32, Vec<&ConnectionInfo>> = HashMap::new();
        for c in inp.connections {
            by_pid.entry(c.pid).or_default().push(c);
        }

        // CPU tracking for sustained-load rule.
        let live: HashSet<u32> = inp.processes.iter().map(|p| p.pid).collect();
        self.high_cpu_since.retain(|pid, _| live.contains(pid));

        let mut findings = Vec::new();
        let mut learned = Vec::new();

        for p in inp.processes {
            if p.pid <= 4 {
                continue;
            }
            if p.cpu >= 60.0 {
                self.high_cpu_since.entry(p.pid).or_insert(inp.now);
            } else {
                self.high_cpu_since.remove(&p.pid);
            }
            let base_key = process_key(p);
            if inp.trusted.contains(&base_key) {
                continue;
            }
            // Signature-dependent rules wait for the background verifier.
            if p.signature.state == SignatureState::Pending {
                continue;
            }

            let conns = by_pid.get(&p.pid).map(|v| v.as_slice()).unwrap_or(&[]);
            let mut new_ports = Vec::new();
            for c in conns {
                let is_listen = c.state == "LISTEN" || (c.state == "BOUND" && c.local_port != 0);
                let exposed = c.scope != crate::model::AddrScope::Loopback;
                if is_listen && exposed && c.state == "LISTEN" {
                    let k = listen_key(c, p.exe.as_deref());
                    if inp.learning {
                        learned.push(k);
                    } else if !inp.listen_baseline.contains(&k) {
                        new_ports.push(format!("{}/{}", c.local_port, if c.ipv6 { "v6" } else { "v4" }));
                    }
                }
            }

            let mut signals = Vec::new();
            signals.extend(rules::masquerade(p));
            signals.extend(rules::signature_and_location(p));
            signals.extend(rules::parent_child(p, p.ppid.and_then(|pp| names.get(&pp).copied())));
            signals.extend(rules::command_line(p));
            signals.extend(rules::network(p, conns));
            signals.extend(rules::listening(p, &new_ports));
            let high = self.high_cpu_since.get(&p.pid).map(|t| (inp.now - t) / 1000).unwrap_or(0);
            signals.extend(rules::resource(p, high));
            if let Some(exe) = &p.exe {
                if let Some(name) = inp.bad_hash_hits.get(&exe.to_ascii_lowercase()) {
                    signals.push(rules::sig(
                        "hash.known_bad",
                        "Bilinen zararlı dosya imzası (hash eşleşmesi)",
                        DEFINITIVE_WEIGHT,
                        name.clone(),
                    ));
                }
            }

            if signals.is_empty() {
                continue;
            }
            let key = match (&p.cmd, signals.iter().any(|s| s.rule == "ps.cmdline" || s.rule == "lolbin.remote")) {
                (Some(cmd), true) => cmdline_key(&base_key, cmd),
                _ => base_key,
            };
            if inp.trusted.contains(&key) {
                continue;
            }
            let (score, severity) = score(&signals);
            if severity == Severity::Info && signals.iter().all(|s| s.rule == "sig.unsigned") {
                // A bare "unsigned" binary in Program Files is normal; don't surface it.
                continue;
            }
            let top = signals.iter().max_by_key(|s| s.weight).map(|s| s.label.clone()).unwrap_or_default();
            findings.push(Finding {
                key,
                entity_kind: "process".into(),
                entity: p.exe.clone().unwrap_or_else(|| p.name.clone()),
                title: top,
                severity,
                score,
                signals,
                first_seen: inp.now,
                last_seen: inp.now,
                pid: Some(p.pid),
                pids: vec![p.pid],
                status: "open".into(),
            });
        }
        // Merge processes sharing a key (e.g. several instances of one unsigned app).
        let mut merged: Vec<Finding> = Vec::with_capacity(findings.len());
        let mut idx: HashMap<String, usize> = HashMap::new();
        for f in findings {
            match idx.get(&f.key) {
                Some(&i) => {
                    let m = &mut merged[i];
                    m.pids.extend(f.pids.iter().copied());
                    if f.score > m.score {
                        let pids = std::mem::take(&mut m.pids);
                        *m = Finding { pids, ..f };
                    }
                }
                None => {
                    idx.insert(f.key.clone(), merged.len());
                    merged.push(f);
                }
            }
        }
        let mut findings = merged;
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.score.cmp(&a.score)));
        EngineOutput { findings, learned_ports: learned }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::rules::sig;

    #[test]
    fn single_signal_capped_at_medium() {
        let (_, s) = score(&[sig("masquerade.path", "x", 50, "")]);
        assert_eq!(s, Severity::Medium);
        let (_, s) = score(&[sig("a", "x", 90, "")]);
        assert_eq!(s, Severity::Medium);
    }

    #[test]
    fn duplicate_rule_counts_once() {
        let (t, _) = score(&[sig("ps.cmdline", "a", 25, ""), sig("ps.cmdline", "b", 15, "")]);
        assert_eq!(t, 25);
    }

    #[test]
    fn critical_needs_two_rules_or_definitive() {
        let (_, s) = score(&[sig("a", "", 50, ""), sig("b", "", 35, "")]);
        assert_eq!(s, Severity::Critical);
        let (_, s) = score(&[sig("hash.known_bad", "", 100, "")]);
        assert_eq!(s, Severity::Critical);
    }

    // ---------- end-to-end scenarios through Engine::evaluate ----------

    use crate::model::{AddrScope, ConnectionInfo, ProcessInfo, Protocol, SignatureInfo};

    fn p(pid: u32, ppid: Option<u32>, name: &str, exe: &str, sig: SignatureState, cmd: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.into(),
            exe: Some(exe.into()),
            cmd: cmd.map(str::to_string),
            cpu: 0.0,
            memory: 1,
            start_time: 0,
            user: None,
            signature: SignatureInfo { state: sig, publisher: None },
            connections: 0,
            critical: false,
            risk: None,
        }
    }

    fn conn(pid: u32, remote: &str, port: u16, state: &str) -> ConnectionInfo {
        ConnectionInfo {
            id: format!("{pid}-{remote}-{port}"),
            protocol: Protocol::Tcp,
            ipv6: false,
            local_addr: "192.168.1.7".into(),
            local_port: 50000,
            remote_addr: Some(remote.into()),
            remote_port: Some(port),
            state: state.into(),
            pid,
            process_name: None,
            started: 0,
            scope: AddrScope::Public,
            hostname: None,
            country: None,
            asn: None,
            risk: None,
        }
    }

    fn listen(pid: u32, port: u16) -> ConnectionInfo {
        ConnectionInfo {
            local_addr: "0.0.0.0".into(),
            local_port: port,
            remote_addr: None,
            remote_port: None,
            state: "LISTEN".into(),
            scope: AddrScope::Unspecified,
            ..conn(pid, "0.0.0.0", 0, "LISTEN")
        }
    }

    struct World {
        procs: Vec<ProcessInfo>,
        conns: Vec<ConnectionInfo>,
        baseline: HashSet<String>,
        trusted: HashSet<String>,
        hashes: HashMap<String, String>,
        learning: bool,
    }

    impl World {
        fn new(procs: Vec<ProcessInfo>, conns: Vec<ConnectionInfo>) -> Self {
            Self { procs, conns, baseline: HashSet::new(), trusted: HashSet::new(), hashes: HashMap::new(), learning: false }
        }
        fn run(&self, engine: &mut Engine, now: i64) -> EngineOutput {
            engine.evaluate(&EngineInput {
                processes: &self.procs,
                connections: &self.conns,
                listen_baseline: &self.baseline,
                learning: self.learning,
                trusted: &self.trusted,
                bad_hash_hits: &self.hashes,
                now,
            })
        }
    }

    const WIN: &str = r"C:\Windows\System32\";

    fn normal_desktop() -> Vec<ProcessInfo> {
        vec![
            p(500, None, "services.exe", &format!("{WIN}services.exe"), SignatureState::Signed, None),
            p(900, Some(500), "svchost.exe", &format!("{WIN}svchost.exe"), SignatureState::Signed, Some("svchost.exe -k netsvcs")),
            p(1200, None, "explorer.exe", r"C:\Windows\explorer.exe", SignatureState::Signed, None),
            p(1300, Some(1200), "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", SignatureState::Signed, None),
        ]
    }

    #[test]
    fn quiet_on_a_normal_desktop() {
        let conns: Vec<_> = (0..40).map(|i| conn(1300, &format!("142.250.1.{i}"), 443, "ESTABLISHED")).collect();
        let out = World::new(normal_desktop(), conns).run(&mut Engine::default(), 0);
        assert!(out.findings.is_empty(), "{:#?}", out.findings);
    }

    #[test]
    fn phishing_chain_escalates() {
        let mut procs = normal_desktop();
        procs.push(p(2000, Some(1200), "WINWORD.EXE", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", SignatureState::Signed, None));
        procs.push(p(
            2001,
            Some(2000),
            "powershell.exe",
            &format!(r"{WIN}WindowsPowerShell\v1.0\powershell.exe"),
            SignatureState::Signed,
            Some("powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
        ));
        let out = World::new(procs, vec![]).run(&mut Engine::default(), 0);
        let f = out.findings.iter().find(|f| f.pid == Some(2001)).expect("powershell finding");
        assert!(f.severity >= Severity::High, "{:?} {}", f.severity, f.score);
        assert!(f.signals.iter().any(|s| s.rule == "lineage.docspawn"));
        // Word itself is not blamed.
        assert!(out.findings.iter().all(|f| f.pid != Some(2000)));
    }

    #[test]
    fn disguised_dropper_is_critical() {
        let mut procs = normal_desktop();
        procs.push(p(3000, Some(1200), "svch0st.exe", r"C:\Users\u\AppData\Local\Temp\svch0st.exe", SignatureState::Unsigned, None));
        let conns = vec![conn(3000, "185.220.101.4", 4444, "ESTABLISHED")];
        let out = World::new(procs, conns).run(&mut Engine::default(), 0);
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.severity, Severity::Critical);
        let rules: HashSet<&str> = f.signals.iter().map(|s| s.rule.as_str()).collect();
        for r in ["masquerade.typo", "loc.temp", "net.unsigned_public", "net.badport"] {
            assert!(rules.contains(r), "missing {r}");
        }
    }

    #[test]
    fn real_system_name_in_wrong_folder() {
        let mut procs = normal_desktop();
        procs.push(p(3100, None, "svchost.exe", r"C:\ProgramData\svchost.exe", SignatureState::Unsigned, None));
        let out = World::new(procs, vec![]).run(&mut Engine::default(), 0);
        let f = &out.findings[0];
        assert_eq!(f.pid, Some(3100));
        assert!(f.severity >= Severity::High, "path masquerade + user-writable unsigned");
    }

    #[test]
    fn known_bad_hash_alone_is_critical() {
        let mut w = World::new(vec![p(4000, None, "tool.exe", r"C:\Tools\tool.exe", SignatureState::Signed, None)], vec![]);
        w.hashes.insert(r"c:\tools\tool.exe".into(), "Win32/Trojan".into());
        let out = w.run(&mut Engine::default(), 0);
        assert_eq!(out.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn trusted_entity_is_silenced() {
        let procs = vec![p(5000, None, "app.exe", r"C:\Users\u\AppData\Local\Temp\app.exe", SignatureState::Unsigned, None)];
        let mut w = World::new(procs, vec![]);
        assert_eq!(w.run(&mut Engine::default(), 0).findings.len(), 1);
        w.trusted.insert(process_key(&w.procs[0]));
        assert!(w.run(&mut Engine::default(), 0).findings.is_empty());
    }

    #[test]
    fn ports_learned_then_new_one_flagged() {
        let procs = vec![p(6000, None, "server.exe", r"C:\Srv\server.exe", SignatureState::Unsigned, None)];
        let mut w = World::new(procs, vec![listen(6000, 8080)]);
        w.learning = true;
        let out = w.run(&mut Engine::default(), 0);
        assert_eq!(out.learned_ports.len(), 1);
        w.baseline.extend(out.learned_ports);
        w.learning = false;
        assert!(w.run(&mut Engine::default(), 0).findings.iter().all(|f| !f.signals.iter().any(|s| s.rule == "port.new")));
        w.conns.push(listen(6000, 4444));
        let out = w.run(&mut Engine::default(), 0);
        let s = out.findings[0].signals.iter().find(|s| s.rule == "port.new").expect("new port");
        assert!(s.evidence.contains("4444") && !s.evidence.contains("8080"));
    }

    #[test]
    fn sustained_cpu_needs_two_minutes() {
        let mut miner = p(7000, None, "x.exe", r"C:\Users\u\AppData\Roaming\x\x.exe", SignatureState::Unsigned, None);
        miner.cpu = 95.0;
        let w = World::new(vec![miner], vec![]);
        let mut e = Engine::default();
        let has_cpu = |o: &EngineOutput| o.findings.iter().any(|f| f.signals.iter().any(|s| s.rule == "res.cpu"));
        assert!(!has_cpu(&w.run(&mut e, 0)));
        assert!(!has_cpu(&w.run(&mut e, 60_000)));
        assert!(has_cpu(&w.run(&mut e, 125_000)));
    }

    #[test]
    fn instances_merge_into_one_finding() {
        let exe = r"C:\Users\u\AppData\Local\Programs\App\app.exe";
        let procs = (0..5).map(|i| p(8000 + i, None, "app.exe", exe, SignatureState::Unsigned, None)).collect();
        let out = World::new(procs, vec![]).run(&mut Engine::default(), 0);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].pids.len(), 5);
    }

    #[test]
    fn pending_signature_waits() {
        let procs = vec![p(9000, None, "a.exe", r"C:\Users\u\AppData\Local\Temp\a.exe", SignatureState::Pending, None)];
        assert!(World::new(procs, vec![]).run(&mut Engine::default(), 0).findings.is_empty());
    }

    #[test]
    fn levels() {
        assert_eq!(score(&[sig("a", "", 5, "")]).1, Severity::Info);
        assert_eq!(score(&[sig("a", "", 15, "")]).1, Severity::Low);
        assert_eq!(score(&[sig("a", "", 30, ""), sig("b", "", 30, "")]).1, Severity::High);
    }
}
