//! Name-resolution and proxy tampering: hosts file, DNS servers per adapter, WinINet proxy
//! and PAC script. These are classic redirection points for banking trojans and adware.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::json;
use tauri::AppHandle;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

use super::{emit, finding, set_findings};
use crate::engine::rules::sig;
use crate::model::{Severity, Signal};
use crate::monitor::{emit_event, event};
use crate::state::Shared;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HostsEntry {
    pub ip: String,
    pub host: String,
    pub risk: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsServer {
    pub adapter: String,
    pub server: String,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Proxy {
    pub enabled: bool,
    pub server: Option<String>,
    pub pac_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetConf {
    pub hosts: Vec<HostsEntry>,
    pub hosts_path: String,
    pub dns: Vec<DnsServer>,
    pub proxy: Proxy,
    pub signals: Vec<Signal>,
}

/// Domains whose redirection or blocking matters: banks/payments, mail, OS & AV updates.
const SENSITIVE: &[&str] = &[
    "google.", "gmail.", "microsoft.", "windowsupdate.", "live.com", "outlook.", "office.", "apple.", "icloud.",
    "paypal.", "facebook.", "instagram.", "whatsapp.", "twitter.", "x.com", "github.", "steam", "epicgames.", "discord.",
    "garanti", "isbank", "akbank", "yapikredi", "ziraat", "halkbank", "vakifbank", "qnb", "denizbank", "enpara", "papara",
    "turkiye.gov", "e-devlet", "binance", "btcturk",
];
const SECURITY: &[&str] = &[
    "virustotal", "malwarebytes", "kaspersky", "eset", "avast", "avg.", "bitdefender", "norton", "mcafee", "sophos",
    "trendmicro", "f-secure", "defender", "wdcp.microsoft", "update.microsoft", "windowsupdate", "abuse.ch",
];

const RESOLVERS: &[(&str, &str)] = &[
    ("8.8.8.8", "Google"), ("8.8.4.4", "Google"), ("1.1.1.1", "Cloudflare"), ("1.0.0.1", "Cloudflare"),
    ("9.9.9.9", "Quad9"), ("149.112.112.112", "Quad9"), ("208.67.222.222", "OpenDNS"), ("208.67.220.220", "OpenDNS"),
    ("94.140.14.14", "AdGuard"), ("94.140.15.15", "AdGuard"), ("76.76.2.0", "Control D"), ("185.228.168.9", "CleanBrowsing"),
    ("2001:4860:4860::8888", "Google"), ("2001:4860:4860::8844", "Google"), ("2606:4700:4700::1111", "Cloudflare"),
    ("2606:4700:4700::1001", "Cloudflare"), ("2620:fe::fe", "Quad9"),
];

fn is_private(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v)) => v.is_private() || v.is_loopback() || v.is_link_local(),
        Ok(std::net::IpAddr::V6(v)) => {
            v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

fn hosts_path() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\drivers\etc\hosts")
}

pub fn parse_hosts(text: &str) -> Vec<HostsEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        for host in parts {
            let h = host.to_ascii_lowercase();
            let sinkhole = matches!(ip, "0.0.0.0" | "127.0.0.1" | "::1" | "::");
            let risk = if h == "localhost" || h.ends_with(".localhost") {
                None
            } else if sinkhole && SECURITY.iter().any(|s| h.contains(s)) {
                Some("Güvenlik/güncelleme sitesi engellenmiş".to_string())
            } else if !sinkhole && SENSITIVE.iter().chain(SECURITY).any(|s| h.contains(s)) {
                Some(format!("Önemli bir site başka adrese yönlendirilmiş ({ip})"))
            } else {
                None
            };
            out.push(HostsEntry { ip: ip.to_string(), host: h, risk });
        }
    }
    out
}

fn dns_servers() -> Vec<DnsServer> {
    let mut out = Vec::new();
    let names = adapter_names();
    for (base, v6) in [
        (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", false),
        (r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces", true),
    ] {
        let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(base, KEY_READ) else { continue };
        for guid in k.enum_keys().flatten() {
            let Ok(i) = k.open_subkey_with_flags(&guid, KEY_READ) else { continue };
            // Static NameServer wins over DHCP-provided servers.
            let raw: String = i
                .get_value::<String, _>("NameServer")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| i.get_value::<String, _>("DhcpNameServer").ok())
                .unwrap_or_default();
            // Only adapters that currently have an address are interesting.
            let active = v6 || i.get_value::<String, _>("DhcpIPAddress").map(|a| a != "0.0.0.0" && !a.is_empty()).unwrap_or(false)
                || i.get_value::<Vec<String>, _>("IPAddress").map(|a| a.iter().any(|x| x != "0.0.0.0")).unwrap_or(false);
            if !active {
                continue;
            }
            for s in raw.split([' ', ',']).map(str::trim).filter(|s| !s.is_empty()) {
                let provider = RESOLVERS.iter().find(|(ip, _)| *ip == s).map(|(_, n)| n.to_string()).or_else(|| is_private(s).then(|| "yerel ağ / modem".into()));
                out.push(DnsServer {
                    adapter: names.iter().find(|(g, _)| g.eq_ignore_ascii_case(&guid)).map(|(_, n)| n.clone()).unwrap_or(guid.clone()),
                    server: s.to_string(),
                    provider,
                });
            }
        }
    }
    out.sort_by(|a, b| a.adapter.cmp(&b.adapter).then(a.server.cmp(&b.server)));
    out.dedup();
    out
}

fn adapter_names() -> Vec<(String, String)> {
    let base = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";
    let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(base, KEY_READ) else { return vec![] };
    k.enum_keys()
        .flatten()
        .filter_map(|g| {
            let n: String = k.open_subkey_with_flags(format!(r"{g}\Connection"), KEY_READ).ok()?.get_value("Name").ok()?;
            Some((g, n))
        })
        .collect()
}

fn proxy() -> Proxy {
    let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", KEY_READ) else {
        return Proxy::default();
    };
    let enabled = k.get_value::<u32, _>("ProxyEnable").unwrap_or(0) == 1;
    Proxy {
        enabled,
        server: k.get_value::<String, _>("ProxyServer").ok().filter(|s| !s.is_empty()),
        pac_url: k.get_value::<String, _>("AutoConfigURL").ok().filter(|s| !s.is_empty()),
    }
}

pub fn evaluate(hosts: &[HostsEntry], dns: &[DnsServer], px: &Proxy) -> Vec<Signal> {
    let mut v = Vec::new();
    let risky: Vec<&HostsEntry> = hosts.iter().filter(|h| h.risk.is_some()).collect();
    if risky.iter().any(|h| !matches!(h.ip.as_str(), "0.0.0.0" | "127.0.0.1" | "::1" | "::")) {
        let ev = risky.iter().take(5).map(|h| format!("{} → {}", h.host, h.ip)).collect::<Vec<_>>().join(", ");
        v.push(sig("net.hosts_redirect", "hosts dosyası önemli siteleri başka adrese yönlendiriyor", 45, ev));
    }
    let blocked: Vec<&&HostsEntry> = risky.iter().filter(|h| matches!(h.ip.as_str(), "0.0.0.0" | "127.0.0.1" | "::1" | "::")).collect();
    if !blocked.is_empty() {
        let ev = blocked.iter().take(5).map(|h| h.host.clone()).collect::<Vec<_>>().join(", ");
        v.push(sig("net.hosts_block_av", "hosts dosyası güvenlik/güncelleme sitelerini engelliyor", 40, ev));
    }
    let unknown: Vec<&DnsServer> = dns.iter().filter(|d| d.provider.is_none()).collect();
    if !unknown.is_empty() {
        let ev = unknown.iter().map(|d| format!("{}: {}", d.adapter, d.server)).collect::<Vec<_>>().join(", ");
        v.push(sig("net.dns_unknown", "Tanınmayan DNS sunucusu kullanılıyor", 15, ev));
    }
    if let Some(pac) = &px.pac_url {
        let local = pac.contains("127.0.0.1") || pac.contains("localhost");
        v.push(sig("net.proxy_pac", "Otomatik proxy betiği (PAC) tanımlı", if local { 15 } else { 25 }, pac.clone()));
    }
    if px.enabled {
        if let Some(s) = &px.server {
            let local = s.contains("127.0.0.1") || s.contains("localhost");
            v.push(sig("net.proxy", "Tarayıcı trafiği proxy üzerinden geçiyor", if local { 10 } else { 20 }, s.clone()));
        }
    }
    v
}

pub fn tick(app: &AppHandle, shared: &Shared) {
    let path = hosts_path();
    let hosts = parse_hosts(&std::fs::read(&path).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default());
    let dns = dns_servers();
    let px = proxy();
    let signals = evaluate(&hosts, &dns, &px);

    // Change detection against the last snapshot persisted in settings.
    let fp = |h: &[HostsEntry], d: &[DnsServer], p: &Proxy| -> (BTreeSet<String>, BTreeSet<String>, String) {
        (
            h.iter().map(|e| format!("{} {}", e.ip, e.host)).collect(),
            d.iter().map(|e| e.server.clone()).collect(),
            format!("{}|{:?}|{:?}", p.enabled, p.server, p.pac_url),
        )
    };
    let cur = fp(&hosts, &dns, &px);
    let st = shared.store.lock();
    let prev: Option<(BTreeSet<String>, BTreeSet<String>, String)> = st.setting("netconf_fp").ok().flatten().and_then(|v| serde_json::from_str(&v).ok());
    let _ = st.set_setting("netconf_fp", &serde_json::to_string(&cur).unwrap_or_default());
    drop(st);
    if let Some(p) = prev {
        let mut changes = Vec::new();
        let added: Vec<&String> = cur.0.difference(&p.0).collect();
        let removed: Vec<&String> = p.0.difference(&cur.0).collect();
        if !added.is_empty() || !removed.is_empty() {
            changes.push(("hosts dosyası değişti", format!("eklenen: {added:?} · kaldırılan: {removed:?}")));
        }
        if cur.1 != p.1 {
            changes.push(("DNS sunucuları değişti", format!("önce: {:?} · şimdi: {:?}", p.1, cur.1)));
        }
        if cur.2 != p.2 {
            changes.push(("Proxy ayarı değişti", format!("önce: {} · şimdi: {}", p.2, cur.2)));
        }
        for (title, detail) in changes {
            let sev = if signals.iter().any(|s| s.weight >= 25) { Severity::Medium } else { Severity::Low };
            emit_event(app, shared, event("net.config_change", sev, title.into(), detail, None, json!({})));
        }
    }
    let f = finding("netconf:system", "netconf", &path, "Ağ ayarlarında yönlendirme".into(), signals.clone(), vec![]);
    set_findings(shared, "netconf:", f.into_iter().filter(|f| f.severity >= Severity::Medium).collect());
    shared.guard.write().netconf = Some(NetConf { hosts, hosts_path: path, dns, proxy: px, signals });
    emit(app, shared);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_rules() {
        let h = parse_hosts(
            "# comment\n127.0.0.1 localhost\n0.0.0.0 ads.example.com tracker.net\n\
             0.0.0.0 www.virustotal.com\n203.0.113.9 www.garanti.com.tr # phishing\n",
        );
        assert_eq!(h.len(), 5);
        let sig = evaluate(&h, &[], &Proxy::default());
        let rules: Vec<&str> = sig.iter().map(|s| s.rule.as_str()).collect();
        assert!(rules.contains(&"net.hosts_redirect"));
        assert!(rules.contains(&"net.hosts_block_av"));
        // Ad-block style sinkholes alone are fine.
        assert!(evaluate(&parse_hosts("0.0.0.0 ads.example.com\n"), &[], &Proxy::default()).is_empty());
    }

    #[test]
    fn dns_and_proxy() {
        let d = vec![DnsServer { adapter: "Wi-Fi".into(), server: "45.9.9.9".into(), provider: None }];
        let p = Proxy { enabled: true, server: Some("10.0.0.5:8080".into()), pac_url: None };
        let s = evaluate(&[], &d, &p);
        assert_eq!(s.len(), 2);
        assert!(is_private("192.168.1.1") && is_private("fe80::1") && !is_private("8.8.8.8"));
    }

    #[test]
    fn live_read() {
        eprintln!("dns {:?}", dns_servers());
        eprintln!("proxy {:?}", proxy());
    }
}
