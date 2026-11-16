//! Raw socket tables via IP Helper (GetExtendedTcpTable / GetExtendedUdpTable).
//! OWNER_MODULE variants give us the owning PID *and* the kernel create timestamp.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE,
    MIB_UDP6ROW_OWNER_MODULE, MIB_UDPROW_OWNER_MODULE, TCP_TABLE_OWNER_MODULE_ALL,
    UDP_TABLE_OWNER_MODULE,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Debug, Clone)]
pub struct RawSocket {
    pub tcp: bool,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub state: u32,
    pub pid: u32,
    /// Unix milliseconds, 0 if the kernel did not record it.
    pub created_ms: i64,
}

fn filetime_to_unix_ms(ft: i64) -> i64 {
    if ft <= 0 {
        return 0;
    }
    ft / 10_000 - 11_644_473_600_000
}

fn port(p: u32) -> u16 {
    u16::from_be(p as u16)
}

pub fn tcp_state_name(s: u32) -> &'static str {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

/// Calls an IP-Helper "extended table" function with grow-and-retry semantics.
/// Returns an 8-byte aligned buffer holding the table.
fn fetch(mut call: impl FnMut(Option<*mut core::ffi::c_void>, &mut u32) -> u32) -> Option<Vec<u64>> {
    let mut size: u32 = 0;
    let _ = call(None, &mut size);
    for _ in 0..4 {
        size += 4096;
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let r = call(Some(buf.as_mut_ptr() as *mut _), &mut size);
        if r == NO_ERROR.0 {
            return Some(buf);
        }
        if r != ERROR_INSUFFICIENT_BUFFER.0 {
            return None;
        }
    }
    None
}

/// Iterate table rows: first u32 is the entry count, rows start at the next
/// offset aligned to the row type.
unsafe fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
    let base = buf.as_ptr() as *const u8;
    let n = *(base as *const u32) as usize;
    let align = std::mem::align_of::<T>().max(4);
    let first = base.add(align.max(4)) as *const T;
    let max = (buf.len() * 8 - align) / std::mem::size_of::<T>();
    (0..n.min(max)).map(|i| *first.add(i)).collect()
}

pub fn snapshot() -> Vec<RawSocket> {
    let mut out = Vec::with_capacity(512);
    unsafe {
        if let Some(buf) = fetch(|p, s| {
            GetExtendedTcpTable(p, s, false, AF_INET.0 as u32, TCP_TABLE_OWNER_MODULE_ALL, 0)
        }) {
            for r in rows::<MIB_TCPROW_OWNER_MODULE>(&buf) {
                let listen = r.dwState == 2;
                out.push(RawSocket {
                    tcp: true,
                    local: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                    local_port: port(r.dwLocalPort),
                    remote: (!listen).then(|| IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes()))),
                    remote_port: (!listen).then(|| port(r.dwRemotePort)),
                    state: r.dwState,
                    pid: r.dwOwningPid,
                    created_ms: filetime_to_unix_ms(r.liCreateTimestamp),
                });
            }
        }
        if let Some(buf) = fetch(|p, s| {
            GetExtendedTcpTable(p, s, false, AF_INET6.0 as u32, TCP_TABLE_OWNER_MODULE_ALL, 0)
        }) {
            for r in rows::<MIB_TCP6ROW_OWNER_MODULE>(&buf) {
                let listen = r.dwState == 2;
                out.push(RawSocket {
                    tcp: true,
                    local: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                    local_port: port(r.dwLocalPort),
                    remote: (!listen).then(|| IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr))),
                    remote_port: (!listen).then(|| port(r.dwRemotePort)),
                    state: r.dwState,
                    pid: r.dwOwningPid,
                    created_ms: filetime_to_unix_ms(r.liCreateTimestamp),
                });
            }
        }
        if let Some(buf) = fetch(|p, s| {
            GetExtendedUdpTable(p, s, false, AF_INET.0 as u32, UDP_TABLE_OWNER_MODULE, 0)
        }) {
            for r in rows::<MIB_UDPROW_OWNER_MODULE>(&buf) {
                out.push(RawSocket {
                    tcp: false,
                    local: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                    local_port: port(r.dwLocalPort),
                    remote: None,
                    remote_port: None,
                    state: 0,
                    pid: r.dwOwningPid,
                    created_ms: filetime_to_unix_ms(r.liCreateTimestamp),
                });
            }
        }
        if let Some(buf) = fetch(|p, s| {
            GetExtendedUdpTable(p, s, false, AF_INET6.0 as u32, UDP_TABLE_OWNER_MODULE, 0)
        }) {
            for r in rows::<MIB_UDP6ROW_OWNER_MODULE>(&buf) {
                out.push(RawSocket {
                    tcp: false,
                    local: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                    local_port: port(r.dwLocalPort),
                    remote: None,
                    remote_port: None,
                    state: 0,
                    pid: r.dwOwningPid,
                    created_ms: filetime_to_unix_ms(r.liCreateTimestamp),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn live_table_has_listeners() {
        let rows = super::snapshot();
        assert!(!rows.is_empty());
        // Every Windows box listens on 135 (RPC endpoint mapper).
        assert!(rows.iter().any(|r| r.tcp && r.state == 2 && r.local_port == 135), "{:?}", &rows[..rows.len().min(5)]);
        assert!(rows.iter().any(|r| r.created_ms > 1_500_000_000_000));
    }
}
