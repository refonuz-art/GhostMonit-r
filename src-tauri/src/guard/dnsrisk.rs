//! Suspicious domain detection on top of the DNS history.
//!
//! Three signals, each judged on the registrable label ("x7fk2q9vhz" in
//! "a.x7fk2q9vhz.top") so random-looking CDN subdomains don't count:
//! - random-looking name (long, high entropy, few vowels / long consonant runs)
//! - many failed lookups (NXDOMAIN) from one program in a short time, the typical
//!   behaviour of malware cycling through generated domains
//! - a top-level domain that is mostly used for abuse, outside a browser

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;

use parking_lot::Mutex;
use serde_json::json;
use tauri::AppHandle;

use super::now_ms;
use crate::model::{Finding, Severity, Signal};
use crate::state::Shared;

pub const NXDOMAIN: u32 = 9003;
const BURST_WINDOW_MS: i64 = 5 * 60_000;
const BURST_COUNT: usize = 25;

const RISKY_TLDS: &[&str] = &[
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim", "work", "rest", "cam", "icu", "buzz",
    "monster", "cyou", "sbs", "lol", "quest", "bond", "cfd",
];

/// Infrastructure whose names are legitimately machine-generated.
const BENIGN_SUFFIXES: &[&str] = &[
    "cloudfront.net", "amazonaws.com", "akamai.net", "akamaiedge.net", "akamaihd.net", "akadns.net", "edgekey.net", "edgesuite.net",
    "azureedge.net", "azurefd.net", "windows.net", "msedge.net", "trafficmanager.net", "azure.com", "microsoft.com", "live.com",
    "office.com", "office.net", "googlevideo.com", "gvt1.com", "gvt2.com", "1e100.net", "googleusercontent.com", "googleapis.com",
    "fastly.net", "fastlylb.net", "cloudflare.net", "cloudflare.com", "steamcontent.com", "steamserver.net", "discord.gg",
    "discordapp.com", "whatsapp.net", "fbcdn.net", "cdninstagram.com", "doubleclick.net", "local", "lan", "home", "arpa",
];

const BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe", "vivaldi.exe", "iexplore.exe", "msedgewebview2.exe"];

/// Second-level labels that combine with a country code ("com.tr", "co.uk").
const SLD_GENERIC: &[&str] = &["com", "co", "net", "org", "gov", "edu", "ac", "gen", "web", "bel", "k12"];

/// The registrable label and the TLD: ("example", "tr") for "www.example.com.tr".
pub fn registrable(name: &str) -> Option<(String, String)> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let tld = labels[labels.len() - 1];
    let mut i = labels.len() - 2;
    if labels.len() >= 3 && tld.len() == 2 && SLD_GENERIC.contains(&labels[i]) {
        i -= 1;
    }
    Some((labels[i].to_string(), tld.to_string()))
}

fn entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = s.chars().count() as f64;
    counts.values().map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// A registrable label that looks generated rather than chosen by a person.
pub fn looks_random(label: &str) -> bool {
    let core: String = label.chars().filter(|c| *c != '-').collect();
    let len = core.chars().count();
    if len < 12 || core.starts_with("xn--") {
        return false;
    }
    let vowels = core.chars().filter(|c| "aeiouy".contains(*c)).count() as f64 / len as f64;
    let digits = core.chars().filter(|c| c.is_ascii_digit()).count() as f64 / len as f64;
    let mut run = 0;
    let mut max_run = 0;
    for c in core.chars() {
        if c.is_ascii_alphabetic() && !"aeiouy".contains(c) {
            run += 1;
            max_run = max_run.max(run);
        } else {
            run = 0;
        }
    }
    let h = entropy(&core);
    h >= 3.5 && (vowels < 0.22 || max_run >= 6 || (digits > 0.25 && digits < 0.75))
}

pub fn benign(name: &str) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    BENIGN_SUFFIXES.iter().any(|s| n == *s || n.ends_with(&format!(".{s}")))
}

pub fn risky_tld(tld: &str) -> bool {
    RISKY_TLDS.contains(&tld)
}

static APP: OnceLock<AppHandle> = OnceLock::new();

pub fn init(app: AppHandle) {
    let _ = APP.set(app);
}

#[derive(Default)]
struct State {
    reported: HashSet<String>,
    failures: HashMap<String, VecDeque<(i64, String)>>,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

pub struct Query<'a> {
    pub name: &'a str,
    pub status: Option<u32>,
    pub pid: Option<u32>,
    pub process: Option<&'a str>,
    pub exe: Option<&'a str>,
}

/// Check one logged query; raises a finding + event the first time something is seen.
pub fn check(shared: &Shared, q: &Query) {
    if !shared.settings.read().dns_alerts || benign(q.name) {
        return;
    }
    let Some((label, tld)) = registrable(q.name) else { return };
    let domain = format!("{label}.{tld}");
    let proc_name = q.process.unwrap_or("bilinmeyen program");
    let is_browser = q.process.is_some_and(|p| BROWSERS.contains(&p.to_ascii_lowercase().as_str()));
    let now = now_ms();
    let mut st = STATE.get_or_init(Default::default).lock();

    // NXDOMAIN burst from one program.
    if q.status == Some(NXDOMAIN) {
        let who = q.exe.or(q.process).unwrap_or("?").to_ascii_lowercase();
        let list = st.failures.entry(who.clone()).or_default();
        list.push_back((now, domain.clone()));
        while list.front().is_some_and(|(t, _)| now - t > BURST_WINDOW_MS) {
            list.pop_front();
        }
        let distinct: HashSet<&String> = list.iter().map(|(_, d)| d).collect();
        if distinct.len() >= BURST_COUNT && who != "?" {
            let sample: Vec<String> = distinct.iter().take(6).map(|s| s.to_string()).collect();
            let n = distinct.len();
            list.clear();
            let key = format!("dnsburst:{who}");
            if st.reported.insert(key.clone()) {
                drop(st);
                raise(
                    shared,
                    key,
                    q.exe.unwrap_or(proc_name).to_string(),
                    format!("{proc_name} çok sayıda var olmayan alan adı sordu"),
                    Severity::High,
                    Signal {
                        rule: "dns.nx_burst".into(),
                        label: format!("5 dakikada {n} farklı alan adı için \"böyle bir ad yok\" yanıtı"),
                        weight: 60,
                        evidence: sample.join(", "),
                    },
                    q,
                );
                return;
            }
        }
        return;
    }

    let random = looks_random(&label);
    let risky = risky_tld(&tld);
    let (sev, signal) = match (random, risky) {
        (true, true) => (
            Severity::High,
            Signal { rule: "dns.random_risky".into(), label: "Rastgele görünen ve kötüye kullanımla bilinen uzantılı alan adı".into(), weight: 60, evidence: q.name.into() },
        ),
        (true, false) => (
            Severity::Medium,
            Signal { rule: "dns.random".into(), label: "Rastgele üretilmiş gibi görünen alan adı".into(), weight: 35, evidence: q.name.into() },
        ),
        (false, true) if !is_browser => (
            Severity::Low,
            Signal { rule: "dns.risky_tld".into(), label: format!("Tarayıcı dışında bir program .{tld} uzantılı alan adı sordu"), weight: 15, evidence: q.name.into() },
        ),
        _ => return,
    };
    let key = format!("domain:{domain}");
    if !st.reported.insert(key.clone()) {
        return;
    }
    drop(st);
    raise(shared, key, domain.clone(), format!("Şüpheli alan adı: {domain}"), sev, signal, q);
}

fn raise(shared: &Shared, key: String, entity: String, title: String, sev: Severity, signal: Signal, q: &Query) {
    let now = now_ms();
    let detail = format!("{} · {}", signal.label, q.process.unwrap_or("program bilinmiyor"));
    crate::watchers::set_finding(
        shared,
        Some(Finding {
            key: key.clone(),
            entity_kind: "domain".into(),
            entity,
            title: title.clone(),
            severity: sev,
            score: signal.weight,
            signals: vec![signal],
            first_seen: now,
            last_seen: now,
            pid: q.pid,
            pids: q.pid.into_iter().collect(),
            status: "open".into(),
        }),
        &key,
    );
    if let Some(app) = APP.get() {
        crate::monitor::emit_event(
            app,
            shared,
            crate::monitor::event(
                "dns.suspicious",
                sev,
                title,
                detail,
                q.exe.map(str::to_string),
                json!({ "key": key, "name": q.name, "pid": q.pid, "pids": q.pid.into_iter().collect::<Vec<_>>(), "exe": q.exe }),
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_label() {
        assert_eq!(registrable("www.example.com.tr"), Some(("example".into(), "tr".into())));
        assert_eq!(registrable("a.b.x7fk2q9vhz.top"), Some(("x7fk2q9vhz".into(), "top".into())));
        assert_eq!(registrable("wpad"), None);
    }

    #[test]
    fn random_names() {
        for r in ["qxkzvbntrwplmh", "k3j9x7q2v8m4zt", "xjwqzkrtvbnmpl"] {
            assert!(looks_random(r), "{r}");
        }
        for ok in ["stackoverflow", "githubusercontent", "microsoftonline", "turkcell", "trendyol", "instagram", "sahibinden", "hepsiburada"] {
            assert!(!looks_random(ok), "{ok}");
        }
        assert!(benign("d1x7k2q9.cloudfront.net"));
        assert!(!benign("evilcloudfront.net"));
    }
}

#[cfg(test)]
mod real_data {
    /// `GM_NAMES=<file>` with one domain per line; prints what would be flagged.
    #[test]
    #[ignore]
    fn scan_real_names() {
        let Ok(path) = std::env::var("GM_NAMES") else { return };
        let text = std::fs::read_to_string(path).unwrap();
        let mut n = 0;
        for name in text.lines() {
            if super::benign(name) {
                continue;
            }
            let Some((label, tld)) = super::registrable(name) else { continue };
            let r = super::looks_random(&label);
            let t = super::risky_tld(&tld);
            if r || t {
                n += 1;
                println!("FLAG {name} random={r} risky_tld={t}");
            }
        }
        println!("checked {} names, flagged {n}", text.lines().count());
    }
}
