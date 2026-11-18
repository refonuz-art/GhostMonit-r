//! Rules written by the user ("Kurallarım"). Every non-empty condition must hold (AND).
//! An `alert` rule adds a signal and lifts the finding to at least the rule's severity —
//! the user's explicit intent overrides the single-signal cap. An `ignore` rule silences
//! every built-in rule for the matching processes.

use serde::{Deserialize, Serialize};

use crate::model::{AddrScope, ConnectionInfo, ProcessInfo, Severity, SignatureState};

pub const MAX_RULES: usize = 200;
const MAX_PATTERN: usize = 300;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Alert,
    Ignore,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Signer {
    Any,
    Signed,
    Unsigned,
    Invalid,
}

fn yes() -> bool {
    true
}
fn medium() -> Severity {
    Severity::Medium
}
fn any() -> Signer {
    Signer::Any
}
fn alert() -> Action {
    Action::Alert
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UserRule {
    pub id: String,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "alert")]
    pub action: Action,
    #[serde(default = "medium")]
    pub severity: Severity,
    /// Process name, `*`/`?` wildcards; without wildcards it must match exactly.
    #[serde(default)]
    pub name_pat: String,
    /// Full path, wildcards; without wildcards it is a "contains" test.
    #[serde(default)]
    pub path_pat: String,
    #[serde(default)]
    pub parent_pat: String,
    #[serde(default)]
    pub cmd_contains: String,
    #[serde(default = "any")]
    pub signer: Signer,
    #[serde(default)]
    pub publisher_contains: String,
    /// Has an established connection to a public address.
    #[serde(default)]
    pub internet: bool,
    /// Comma separated remote ports (any established connection to one of them).
    #[serde(default)]
    pub remote_ports: String,
    /// Listens on a non-loopback port.
    #[serde(default)]
    pub listens: bool,
    #[serde(default)]
    pub note: String,
}

impl UserRule {
    pub fn rule_id(&self) -> String {
        format!("user.{}", self.id)
    }

    fn has_condition(&self) -> bool {
        !self.name_pat.trim().is_empty()
            || !self.path_pat.trim().is_empty()
            || !self.parent_pat.trim().is_empty()
            || !self.cmd_contains.trim().is_empty()
            || self.signer != Signer::Any
            || !self.publisher_contains.trim().is_empty()
            || self.internet
            || !self.remote_ports.trim().is_empty()
            || self.listens
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() || self.id.len() > 64 || !self.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("Kural kimliği geçersiz".into());
        }
        if self.name.trim().is_empty() || self.name.chars().count() > 80 {
            return Err("Kurala 1–80 karakterlik bir ad verin".into());
        }
        if !self.has_condition() {
            return Err("En az bir koşul girin; koşulsuz kural her işlemi yakalar".into());
        }
        for p in [&self.name_pat, &self.path_pat, &self.parent_pat, &self.cmd_contains, &self.publisher_contains, &self.note] {
            if p.chars().count() > MAX_PATTERN {
                return Err(format!("Alanlar en fazla {MAX_PATTERN} karakter olabilir"));
            }
        }
        parse_ports(&self.remote_ports)?;
        if self.action == Action::Alert && self.severity == Severity::Info {
            return Err("Uyarı kuralı en az Düşük seviyede olmalı".into());
        }
        Ok(())
    }

    /// Evidence text when the rule matches this process.
    pub fn matches(&self, p: &ProcessInfo, parent: Option<&str>, conns: &[&ConnectionInfo]) -> Option<String> {
        let mut ev: Vec<String> = Vec::new();
        if !self.name_pat.trim().is_empty() {
            if !glob(&self.name_pat, &p.name, false) {
                return None;
            }
            ev.push(format!("ad {}", p.name));
        }
        if !self.path_pat.trim().is_empty() {
            let exe = p.exe.as_deref()?;
            if !glob(&self.path_pat, exe, true) {
                return None;
            }
            ev.push(exe.to_string());
        }
        if !self.parent_pat.trim().is_empty() {
            let parent = parent?;
            if !glob(&self.parent_pat, parent, false) {
                return None;
            }
            ev.push(format!("üst işlem {parent}"));
        }
        if !self.cmd_contains.trim().is_empty() {
            let cmd = p.cmd.as_deref()?;
            if !lower(cmd).contains(&lower(self.cmd_contains.trim())) {
                return None;
            }
            ev.push(format!("komut satırında “{}”", self.cmd_contains.trim()));
        }
        match self.signer {
            Signer::Any => {}
            Signer::Signed if p.signature.state == SignatureState::Signed => ev.push("imzalı".into()),
            Signer::Unsigned if p.signature.state == SignatureState::Unsigned => ev.push("imzasız".into()),
            Signer::Invalid if p.signature.state == SignatureState::Invalid => ev.push("geçersiz imza".into()),
            _ => return None,
        }
        if !self.publisher_contains.trim().is_empty() {
            let publ = p.signature.publisher.as_deref()?;
            if !lower(publ).contains(&lower(self.publisher_contains.trim())) {
                return None;
            }
            ev.push(format!("yayıncı {publ}"));
        }
        let established: Vec<&&ConnectionInfo> =
            conns.iter().filter(|c| c.state == "ESTABLISHED" && c.remote_addr.is_some()).collect();
        if self.internet {
            let n = established.iter().filter(|c| c.scope == AddrScope::Public).count();
            if n == 0 {
                return None;
            }
            ev.push(format!("{n} internet bağlantısı"));
        }
        let ports = parse_ports(&self.remote_ports).unwrap_or_default();
        if !ports.is_empty() {
            let hit = established.iter().find(|c| c.remote_port.is_some_and(|p| ports.contains(&p)))?;
            ev.push(format!("{}:{}", hit.remote_addr.as_deref().unwrap_or("?"), hit.remote_port.unwrap_or(0)));
        }
        if self.listens {
            let l = conns.iter().find(|c| c.state == "LISTEN" && c.scope != AddrScope::Loopback)?;
            ev.push(format!("{} portunu dinliyor", l.local_port));
        }
        Some(ev.join(" · "))
    }
}

pub fn weight_of(sev: Severity) -> u32 {
    match sev {
        Severity::Info => 5,
        Severity::Low => 15,
        Severity::Medium => 30,
        Severity::High => 55,
        Severity::Critical => 80,
    }
}

fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    s.split([',', ' ', ';'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| t.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| format!("Geçersiz port: {t}")))
        .collect()
}

fn lower(s: &str) -> String {
    s.to_lowercase().replace('/', "\\")
}

/// Case-insensitive wildcard match (`*` any run, `?` one char). Without wildcards:
/// equality, or substring when `contains_if_plain`.
pub fn glob(pattern: &str, text: &str, contains_if_plain: bool) -> bool {
    let p: Vec<char> = lower(pattern.trim()).chars().collect();
    let t: Vec<char> = lower(text).chars().collect();
    if !p.iter().any(|c| *c == '*' || *c == '?') {
        let (p, t): (String, String) = (p.into_iter().collect(), t.into_iter().collect());
        return if contains_if_plain { t.contains(&p) } else { t == p };
    }
    // Iterative matcher with single backtrack point.
    let (mut i, mut j) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while j < t.len() {
        if i < p.len() && (p[i] == '?' || p[i] == t[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            mark = j;
            i += 1;
        } else if let Some(s) = star {
            i = s + 1;
            mark += 1;
            j = mark;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}

pub fn load(store: &crate::store::Store) -> Vec<UserRule> {
    store
        .setting("user_rules")
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_str::<Vec<UserRule>>(&v).ok())
        .unwrap_or_default()
}

pub fn save(store: &crate::store::Store, rules: &[UserRule]) -> Result<(), String> {
    if rules.len() > MAX_RULES {
        return Err(format!("En fazla {MAX_RULES} kural tanımlanabilir"));
    }
    let mut ids = std::collections::HashSet::new();
    for r in rules {
        r.validate().map_err(|e| format!("“{}”: {e}", r.name))?;
        if !ids.insert(&r.id) {
            return Err("Aynı kimlikli iki kural var".into());
        }
    }
    store
        .set_setting("user_rules", &serde_json::to_string(rules).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Protocol, SignatureInfo};

    fn rule() -> UserRule {
        serde_json::from_str(r#"{"id":"r1","name":"t"}"#).unwrap()
    }

    fn proc(name: &str, exe: &str, state: SignatureState, cmd: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid: 10,
            ppid: Some(1),
            name: name.into(),
            exe: Some(exe.into()),
            cmd: cmd.map(Into::into),
            cpu: 0.0,
            memory: 0,
            start_time: 0,
            user: None,
            signature: SignatureInfo { state, publisher: Some("Valve Corp.".into()) },
            connections: 0,
            critical: false,
            risk: None,
        }
    }

    fn conn(port: u16, scope: AddrScope, state: &str) -> ConnectionInfo {
        ConnectionInfo {
            id: "x".into(),
            protocol: Protocol::Tcp,
            ipv6: false,
            local_addr: "0.0.0.0".into(),
            local_port: 7000,
            remote_addr: Some("8.8.8.8".into()),
            remote_port: Some(port),
            state: state.into(),
            pid: 10,
            process_name: None,
            started: 0,
            scope,
            hostname: None,
            country: None,
            asn: None,
            risk: None,
        }
    }

    #[test]
    fn wildcards() {
        assert!(glob("*.exe", "a.EXE", false));
        assert!(glob(r"C:\Users\*\Downloads\*", r"c:\users\ali\downloads\x\y.exe", true));
        assert!(!glob(r"C:\Users\*\Downloads\*.exe", r"c:\users\ali\desktop\y.exe", true));
        assert!(glob("svch?st.exe", "svch0st.exe", false));
        assert!(glob("temp", r"C:\Temp\a.exe", true));
        assert!(!glob("a.exe", "aa.exe", false));
        assert!(glob("oyunlar", r"D:\OYUNLAR\a.exe", true));
    }

    #[test]
    fn needs_a_condition_and_valid_ports() {
        let mut r = rule();
        assert!(r.validate().is_err());
        r.remote_ports = "4444, 80".into();
        assert!(r.validate().is_ok());
        r.remote_ports = "70000".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn all_conditions_must_hold() {
        let mut r = rule();
        r.path_pat = r"*\Downloads\*".into();
        r.signer = Signer::Unsigned;
        let p = proc("x.exe", r"C:\Users\u\Downloads\x.exe", SignatureState::Unsigned, None);
        assert!(r.matches(&p, None, &[]).is_some());
        let signed = proc("x.exe", r"C:\Users\u\Downloads\x.exe", SignatureState::Signed, None);
        assert!(r.matches(&signed, None, &[]).is_none());
        r.internet = true;
        assert!(r.matches(&p, None, &[]).is_none());
        let c = conn(443, AddrScope::Public, "ESTABLISHED");
        assert!(r.matches(&p, None, &[&c]).unwrap().contains("internet"));
        r.remote_ports = "4444".into();
        assert!(r.matches(&p, None, &[&c]).is_none());
        let bad = conn(4444, AddrScope::Public, "ESTABLISHED");
        assert!(r.matches(&p, None, &[&c, &bad]).unwrap().contains("8.8.8.8:4444"));
    }

    #[test]
    fn parent_cmd_publisher() {
        let mut r = rule();
        r.parent_pat = "winword.exe".into();
        r.cmd_contains = "-ENC".into();
        r.publisher_contains = "valve".into();
        let p = proc("powershell.exe", r"C:\w\powershell.exe", SignatureState::Signed, Some("powershell -enc AAA"));
        assert!(r.matches(&p, Some("WINWORD.EXE"), &[]).is_some());
        assert!(r.matches(&p, Some("explorer.exe"), &[]).is_none());
        assert!(r.matches(&p, None, &[]).is_none());
    }
}
