//! Home network devices from the Windows neighbour (ARP) table.
//!
//! Passive by default: we only read what Windows already knows. "Ağı tara" (sweep) is
//! started by the user and sends one ARP request to each address of the local /24 so quiet
//! devices show up too. A router MAC that suddenly changes is a classic ARP-spoofing sign.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::AppHandle;
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2, SendARP};
use windows::Win32::Networking::WinSock::{AF_INET, NlnsIncomplete, NlnsUnreachable};

use super::{emit, finding, now_ms, set_findings};
use crate::engine::rules::sig;
use crate::model::Severity;
use crate::monitor::{emit_event, event};
use crate::state::Shared;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LanDevice {
    pub ip: String,
    pub mac: String,
    pub vendor: Option<String>,
    pub name: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub online: bool,
    pub gateway: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Known {
    ip: String,
    first: i64,
    last: i64,
    name: Option<String>,
}

/// A small set of well-known OUIs; anything else is shown as unknown rather than guessed.
const OUI: &[(&str, &str)] = &[
    ("B8:27:EB", "Raspberry Pi"), ("DC:A6:32", "Raspberry Pi"), ("E4:5F:01", "Raspberry Pi"), ("D8:3A:DD", "Raspberry Pi"),
    ("2C:CF:67", "Raspberry Pi"), ("00:50:56", "VMware"), ("00:0C:29", "VMware"), ("08:00:27", "VirtualBox"),
    ("00:15:5D", "Hyper-V"), ("52:54:00", "QEMU/KVM"), ("00:17:88", "Philips Hue"), ("24:0A:C4", "Espressif"),
    ("30:AE:A4", "Espressif"), ("A4:CF:12", "Espressif"), ("84:F3:EB", "Espressif"), ("CC:50:E3", "Espressif"),
    ("EC:FA:BC", "Espressif"), ("00:11:32", "Synology"), ("24:5E:BE", "QNAP"), ("00:0E:58", "Sonos"),
    ("94:9F:3E", "Sonos"), ("00:03:93", "Apple"), ("00:1C:B3", "Apple"), ("00:1E:C2", "Apple"), ("00:16:6C", "Samsung"),
    ("00:E0:4C", "Realtek"), ("00:E0:FC", "Huawei"), ("00:50:F2", "Microsoft"), ("00:1D:0F", "TP-Link"),
    ("00:27:19", "TP-Link"), ("00:0F:B5", "Netgear"), ("00:09:5B", "Netgear"), ("00:05:5D", "D-Link"),
    ("00:0D:88", "D-Link"), ("00:A0:C5", "ZyXEL"), ("00:13:49", "ZyXEL"), ("00:1D:AA", "DrayTek"),
    ("00:04:0E", "AVM"), ("00:1C:4A", "AVM"), ("00:24:FE", "AVM"),
];

fn mac_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":")
}

pub fn vendor(mac: &str) -> Option<String> {
    let first = mac.as_bytes().get(1).copied().and_then(|c| (c as char).to_digit(16)).unwrap_or(0);
    if first & 0x2 != 0 {
        return Some("rastgele MAC (gizlilik modu)".into());
    }
    let p = &mac.get(..8)?;
    OUI.iter().find(|(o, _)| o == p).map(|(_, v)| v.to_string())
}

/// (ip, mac) of reachable neighbours on IPv4, excluding broadcast/multicast entries.
pub fn neighbours() -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    unsafe {
        let mut t: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        if GetIpNetTable2(AF_INET, &mut t).is_err() || t.is_null() {
            return out;
        }
        let n = (*t).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*t).Table.as_ptr(), n);
        for r in rows {
            if r.State == NlnsUnreachable || r.State == NlnsIncomplete || r.PhysicalAddressLength != 6 {
                continue;
            }
            let mac = &r.PhysicalAddress[..6];
            if mac.iter().all(|b| *b == 0) || mac.iter().all(|b| *b == 0xFF) || mac[0] & 1 == 1 {
                continue; // empty, broadcast, multicast
            }
            let ip = Ipv4Addr::from(u32::from_be(r.Address.Ipv4.sin_addr.S_un.S_addr));
            if !ip.is_private() || ip.octets()[3] == 255 || ip.octets()[3] == 0 {
                continue;
            }
            out.push((ip, mac_str(mac)));
        }
        FreeMibTable(t as *const _);
    }
    out.sort();
    out.dedup();
    out
}

/// The machine's primary private IPv4 (no packet is sent; connect() only picks a route).
pub fn local_ip() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v) if v.is_private() => Some(v),
        _ => None,
    }
}

fn gateway_guess(ip: &Ipv4Addr) -> bool {
    matches!(ip.octets()[3], 1 | 254)
}

/// Active sweep of the local /24 (user-initiated). Returns how many addresses answered.
pub fn sweep() -> Result<usize, String> {
    let me = local_ip().ok_or("Yerel ağ adresi bulunamadı (özel bir ağa bağlı değilsiniz)")?;
    let [a, b, c, _] = me.octets();
    let targets: Vec<Ipv4Addr> = (1..=254u8).map(|d| Ipv4Addr::new(a, b, c, d)).filter(|ip| *ip != me).collect();
    let hits = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for chunk in targets.chunks(16) {
            let hits = &hits;
            scope.spawn(move || {
                for ip in chunk {
                    let mut mac = [0u8; 8];
                    let mut len = 6u32;
                    let dst = u32::from_ne_bytes(ip.octets());
                    if unsafe { SendARP(dst, 0, mac.as_mut_ptr() as *mut _, &mut len) } == 0 {
                        hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            });
        }
    });
    Ok(hits.into_inner())
}

pub fn tick(app: &AppHandle, shared: &Shared) {
    let now = now_ms();
    let seen = neighbours();
    let st = shared.store.lock();
    let stored: Option<BTreeMap<String, Known>> = st.setting("lan_known").ok().flatten().and_then(|v| serde_json::from_str(&v).ok());
    let baseline = stored.is_none();
    let mut known = stored.unwrap_or_default();
    let mut new_devices = Vec::new();
    let mut gw_changes = Vec::new();
    for (ip, mac) in &seen {
        let ips = ip.to_string();
        // Gateway MAC swap: the address that looks like the router now answers with a
        // MAC we have never associated with it before.
        if gateway_guess(ip) {
            let prev_owner = known.iter().find(|(m, k)| k.ip == ips && *m != mac).map(|(m, _)| m.clone());
            if let Some(prev) = prev_owner {
                if !known.contains_key(mac) {
                    gw_changes.push(format!("{ips}: {prev} → {mac}"));
                }
            }
        }
        match known.get_mut(mac) {
            Some(k) => {
                k.ip = ips;
                k.last = now;
            }
            None => {
                known.insert(mac.clone(), Known { ip: ips.clone(), first: now, last: now, name: None });
                if !baseline {
                    new_devices.push((ips, mac.clone()));
                }
            }
        }
    }
    if known.len() > 1000 {
        let mut v: Vec<(String, i64)> = known.iter().map(|(m, k)| (m.clone(), k.last)).collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.1));
        let keep: std::collections::HashSet<String> = v.into_iter().take(1000).map(|x| x.0).collect();
        known.retain(|m, _| keep.contains(m));
    }
    let _ = st.set_setting("lan_known", &serde_json::to_string(&known).unwrap_or_default());
    drop(st);

    for (ip, mac) in &new_devices {
        let v = vendor(mac).unwrap_or_else(|| "üretici bilinmiyor".into());
        emit_event(
            app,
            shared,
            event("lan.new_device", Severity::Low, format!("Ağınızda yeni cihaz: {ip}"), format!("{mac} · {v}"), Some(ip.clone()), json!({ "ip": ip, "mac": mac })),
        );
    }
    let f = (!gw_changes.is_empty())
        .then(|| {
            finding(
                "lan:gateway",
                "network",
                "Yerel ağ",
                "Modem/yönlendirici adresi farklı bir cihaza geçti".into(),
                vec![sig("lan.gateway_mac", "Yönlendiricinin donanım adresi değişti (ARP zehirleme olabilir)", 45, gw_changes.join(", "))],
                vec![],
            )
        })
        .flatten();
    if f.is_some() {
        set_findings(shared, "lan:", f.into_iter().collect());
    }
    let online: std::collections::HashSet<&String> = seen.iter().map(|(_, m)| m).collect();
    let mut list: Vec<LanDevice> = known
        .iter()
        .map(|(mac, k)| LanDevice {
            ip: k.ip.clone(),
            mac: mac.clone(),
            vendor: vendor(mac),
            name: k.name.clone(),
            first_seen: k.first,
            last_seen: k.last,
            online: online.contains(mac),
            gateway: k.ip.parse().map(|i| gateway_guess(&i)).unwrap_or(false),
        })
        .collect();
    list.sort_by(|a, b| {
        b.online.cmp(&a.online).then_with(|| {
            let ip = |s: &str| s.parse::<Ipv4Addr>().map(u32::from).unwrap_or(u32::MAX);
            ip(&a.ip).cmp(&ip(&b.ip))
        })
    });
    {
        let mut g = shared.guard.write();
        g.lan = list;
        g.lan_scanned = Some(now);
    }
    emit(app, shared);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendors() {
        assert_eq!(vendor("B8:27:EB:00:11:22").as_deref(), Some("Raspberry Pi"));
        assert!(vendor("DA:00:00:00:00:01").unwrap().contains("rastgele"));
        assert_eq!(vendor("00:00:01:00:00:01"), None);
    }

    #[test]
    fn live_neighbours() {
        eprintln!("local {:?}", local_ip());
        for (ip, mac) in neighbours() {
            eprintln!("{ip} {mac} {:?}", vendor(&mac));
        }
    }
}
