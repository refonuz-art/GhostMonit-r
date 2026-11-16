use std::collections::HashMap;
use std::net::IpAddr;

use crate::model::{AddrScope, ConnectionInfo, Protocol};
use crate::winapi::tcp_table::{self, tcp_state_name, RawSocket};

pub fn scope_of(ip: &IpAddr) -> AddrScope {
    if ip.is_unspecified() {
        return AddrScope::Unspecified;
    }
    if ip.is_loopback() {
        return AddrScope::Loopback;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_link_local() || v4.is_broadcast() || v4.is_multicast()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64
            {
                AddrScope::Private
            } else {
                AddrScope::Public
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return scope_of(&IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            if (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80 || v6.is_multicast() {
                AddrScope::Private
            } else {
                AddrScope::Public
            }
        }
    }
}

/// Tracks first-seen times so connections without a kernel timestamp still get one.
#[derive(Default)]
pub struct NetworkCollector {
    first_seen: HashMap<String, i64>,
}

pub fn key_of(s: &RawSocket) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        if s.tcp { "T" } else { "U" },
        s.local,
        s.local_port,
        s.remote.map(|r| r.to_string()).unwrap_or_default(),
        s.remote_port.unwrap_or(0),
        s.pid
    )
}

impl NetworkCollector {
    pub fn collect(&mut self, names: &HashMap<u32, String>) -> Vec<ConnectionInfo> {
        let now = chrono::Utc::now().timestamp_millis();
        let raw = tcp_table::snapshot();
        let mut seen = HashMap::with_capacity(raw.len());
        let out = raw
            .into_iter()
            .map(|s| {
                let id = key_of(&s);
                let first = *self.first_seen.get(&id).unwrap_or(&now);
                seen.insert(id.clone(), first);
                let started = if s.created_ms > 0 { s.created_ms } else { first };
                let scope = match &s.remote {
                    Some(r) => scope_of(r),
                    None => scope_of(&s.local),
                };
                ConnectionInfo {
                    id,
                    protocol: if s.tcp { Protocol::Tcp } else { Protocol::Udp },
                    ipv6: s.local.is_ipv6(),
                    local_addr: s.local.to_string(),
                    local_port: s.local_port,
                    remote_addr: s.remote.map(|r| r.to_string()),
                    remote_port: s.remote_port,
                    state: if s.tcp { tcp_state_name(s.state).to_string() } else { "BOUND".into() },
                    pid: s.pid,
                    process_name: names.get(&s.pid).cloned(),
                    started,
                    scope,
                    hostname: None,
                    country: None,
                    asn: None,
                    risk: None,
                }
            })
            .collect();
        self.first_seen = seen;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes() {
        assert_eq!(scope_of(&"127.0.0.1".parse().unwrap()), AddrScope::Loopback);
        assert_eq!(scope_of(&"192.168.1.5".parse().unwrap()), AddrScope::Private);
        assert_eq!(scope_of(&"100.64.0.1".parse().unwrap()), AddrScope::Private);
        assert_eq!(scope_of(&"8.8.8.8".parse().unwrap()), AddrScope::Public);
        assert_eq!(scope_of(&"fe80::1".parse().unwrap()), AddrScope::Private);
        assert_eq!(scope_of(&"2606:4700::1111".parse().unwrap()), AddrScope::Public);
        assert_eq!(scope_of(&"0.0.0.0".parse().unwrap()), AddrScope::Unspecified);
    }
}
