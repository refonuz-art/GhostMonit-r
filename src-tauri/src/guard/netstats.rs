//! Per-program TCP data usage from the kernel's extended TCP statistics (EStats).
//!
//! Collection has to be switched on per connection with SetPerTcpConnectionEStats, which
//! requires administrator rights. Without elevation this module reports that honestly and
//! shows nothing rather than guessing. Counters cover TCP only (UDP traffic such as QUIC
//! and DNS is not included) and start when Ghost Monitor starts watching a connection.

use std::collections::HashMap;
use std::net::IpAddr;

use parking_lot::Mutex;
use serde::Serialize;
use windows::Win32::NetworkManagement::IpHelper::{
    GetPerTcp6ConnectionEStats, GetPerTcpConnectionEStats, SetPerTcp6ConnectionEStats, SetPerTcpConnectionEStats, MIB_TCP6ROW,
    MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCP_STATE, TCP_ESTATS_DATA_ROD_v0, TCP_ESTATS_DATA_RW_v0, TcpConnectionEstatsData,
};
use windows::Win32::Networking::WinSock::{IN6_ADDR, IN6_ADDR_0};

use crate::state::Shared;
use crate::winapi::tcp_table::{snapshot, RawSocket};

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcUsage {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// bytes per second over the last sample
    pub rate_in: u64,
    pub rate_out: u64,
    pub connections: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetUsage {
    pub available: bool,
    pub reason: Option<String>,
    pub since: Option<i64>,
    pub sampled: Option<i64>,
    pub processes: Vec<ProcUsage>,
}

type ConnKey = (u32, IpAddr, u16, IpAddr, u16);

#[derive(Default)]
struct Tracker {
    /// last cumulative counters per live connection
    conns: HashMap<ConnKey, (u64, u64)>,
    /// bytes from connections that have closed, per pid
    closed: HashMap<u32, (u64, u64)>,
    prev_total: HashMap<u32, (u64, u64)>,
    last_at: Option<std::time::Instant>,
    since: Option<i64>,
}

static TRACKER: Mutex<Option<Tracker>> = parking_lot::const_mutex(None);

fn port_be(p: u16) -> u32 {
    p.to_be() as u32
}

fn v6(ip: &std::net::Ipv6Addr) -> IN6_ADDR {
    IN6_ADDR { u: IN6_ADDR_0 { Byte: ip.octets() } }
}

/// Enable (idempotent) and read the data counters of one connection: (in, out).
fn read(s: &RawSocket) -> Option<(u64, u64)> {
    let (IpAddr::V4(l), Some(IpAddr::V4(r))) = (s.local, s.remote) else {
        return read6(s);
    };
    let row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE(s.state as i32) },
        dwLocalAddr: u32::from_ne_bytes(l.octets()),
        dwLocalPort: port_be(s.local_port),
        dwRemoteAddr: u32::from_ne_bytes(r.octets()),
        dwRemotePort: port_be(s.remote_port?),
    };
    let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: true };
    let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
    unsafe {
        let rw_b = std::slice::from_raw_parts(&rw as *const _ as *const u8, std::mem::size_of_val(&rw));
        let _ = SetPerTcpConnectionEStats(&row, TcpConnectionEstatsData, rw_b, 0, 0);
        let rod_b = std::slice::from_raw_parts_mut(&mut rod as *mut _ as *mut u8, std::mem::size_of_val(&rod));
        if GetPerTcpConnectionEStats(&row, TcpConnectionEstatsData, None, 0, None, 0, Some(rod_b), 0) != 0 {
            return None;
        }
    }
    Some((rod.DataBytesIn, rod.DataBytesOut))
}

fn read6(s: &RawSocket) -> Option<(u64, u64)> {
    let (IpAddr::V6(l), Some(IpAddr::V6(r))) = (s.local, s.remote) else { return None };
    let row = MIB_TCP6ROW {
        State: MIB_TCP_STATE(s.state as i32),
        LocalAddr: v6(&l),
        dwLocalScopeId: 0,
        dwLocalPort: port_be(s.local_port),
        RemoteAddr: v6(&r),
        dwRemoteScopeId: 0,
        dwRemotePort: port_be(s.remote_port?),
    };
    let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: true };
    let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
    unsafe {
        let rw_b = std::slice::from_raw_parts(&rw as *const _ as *const u8, std::mem::size_of_val(&rw));
        let _ = SetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsData, rw_b, 0, 0);
        let rod_b = std::slice::from_raw_parts_mut(&mut rod as *mut _ as *mut u8, std::mem::size_of_val(&rod));
        if GetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsData, None, 0, None, 0, Some(rod_b), 0) != 0 {
            return None;
        }
    }
    Some((rod.DataBytesIn, rod.DataBytesOut))
}

pub fn sample(shared: &Shared) -> NetUsage {
    if !crate::winapi::elevation::is_elevated() {
        *TRACKER.lock() = None;
        return NetUsage {
            available: false,
            reason: Some("Program başına veri kullanımı Windows'ta yalnızca yönetici yetkisiyle ölçülebilir. Ghost Monitor'ü yönetici olarak yeniden başlatın.".into()),
            ..Default::default()
        };
    }
    let mut guard = TRACKER.lock();
    let t = guard.get_or_insert_with(|| Tracker { since: Some(super::now_ms()), ..Default::default() });
    let mut live: HashMap<ConnKey, (u64, u64)> = HashMap::new();
    let mut conn_count: HashMap<u32, u32> = HashMap::new();
    for s in snapshot().into_iter().filter(|s| s.tcp && s.state == 5 && s.remote.is_some() && s.pid > 4) {
        let key = (s.pid, s.local, s.local_port, s.remote.unwrap_or(s.local), s.remote_port.unwrap_or(0));
        if let Some(v) = read(&s) {
            live.insert(key, v);
            *conn_count.entry(s.pid).or_default() += 1;
        }
    }
    // Connections that vanished keep their last counters in the per-pid closed bucket.
    for (k, v) in t.conns.drain() {
        if !live.contains_key(&k) {
            let e = t.closed.entry(k.0).or_default();
            e.0 += v.0;
            e.1 += v.1;
        }
    }
    t.conns = live;
    let mut totals: HashMap<u32, (u64, u64)> = t.closed.clone();
    for (k, v) in &t.conns {
        let e = totals.entry(k.0).or_default();
        e.0 += v.0;
        e.1 += v.1;
    }
    let dt = t.last_at.map(|a| a.elapsed().as_secs_f64()).filter(|d| *d > 0.2);
    t.last_at = Some(std::time::Instant::now());
    let procs = shared.processes.read();
    let mut out: Vec<ProcUsage> = totals
        .iter()
        .filter(|(_, (i, o))| i + o > 0)
        .map(|(pid, (i, o))| {
            let prev = t.prev_total.get(pid).copied().unwrap_or((*i, *o));
            let rate = |now: u64, before: u64| dt.map(|d| (now.saturating_sub(before) as f64 / d) as u64).unwrap_or(0);
            let p = procs.iter().find(|p| p.pid == *pid);
            ProcUsage {
                pid: *pid,
                name: p.map(|p| p.name.clone()).unwrap_or_else(|| format!("PID {pid} (kapandı)")),
                exe: p.and_then(|p| p.exe.clone()),
                bytes_in: *i,
                bytes_out: *o,
                rate_in: rate(*i, prev.0),
                rate_out: rate(*o, prev.1),
                connections: conn_count.get(pid).copied().unwrap_or(0),
            }
        })
        .collect();
    drop(procs);
    t.prev_total = totals;
    // Forget processes that are gone and have been for a while (bounded memory).
    if t.closed.len() > 2000 {
        t.closed.retain(|pid, _| conn_count.contains_key(pid));
    }
    out.sort_by(|a, b| (b.bytes_in + b.bytes_out).cmp(&(a.bytes_in + a.bytes_out)));
    out.truncate(100);
    NetUsage { available: true, reason: None, since: t.since, sampled: Some(super::now_ms()), processes: out }
}
