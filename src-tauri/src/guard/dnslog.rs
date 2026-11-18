//! DNS query history: which program asked for which domain.
//!
//! - Elevated: a real-time ETW session on Microsoft-Windows-DNS-Client (event 3008, "query
//!   completed") gives every query with the process that made it.
//! - Standard user: ETW sessions need admin, so the Windows DNS cache is read every 15 s
//!   instead. The cache does not record the asking process; it is attributed by matching the
//!   resolved addresses to live/recent connections, and left empty when nothing matches.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rusqlite::params;
use serde::Serialize;
use windows::core::{s, w, GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::Dns::{DnsFree, DnsFreeFlat, DNS_TYPE_A};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use super::now_ms;
use crate::state::Shared;

const SESSION: &str = "GhostMonitor-DNS";
const DNS_CLIENT: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
const EV_QUERY_COMPLETED: u16 = 3008;
const QTYPE_PTR: u32 = 12;

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsStatus {
    /// "etw" | "cache" | "off"
    pub mode: String,
    pub note: Option<String>,
    pub since: Option<i64>,
    pub logged: u64,
}

#[derive(Debug, Clone)]
struct Rec {
    ts: i64,
    name: String,
    qtype: u32,
    status: Option<u32>,
    pid: Option<u32>,
    results: String,
    source: &'static str,
}

pub fn spawn(shared: Arc<Shared>) {
    std::thread::Builder::new()
        .name("dnslog".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            let mut note = None;
            if crate::winapi::elevation::is_elevated() {
                match etw_start() {
                    Ok(rx) => {
                        set_status(&shared, "etw", None);
                        etw_drain(&shared, rx);
                        note = Some("ETW oturumu kapandı; önbellek okumaya geçildi".to_string());
                    }
                    Err(e) => note = Some(format!("ETW başlatılamadı ({e}); önbellek okunuyor")),
                }
            }
            set_status(&shared, "cache", note);
            cache_loop(&shared);
        })
        .expect("spawn dnslog");
}

fn set_status(shared: &Shared, mode: &str, note: Option<String>) {
    let mut s = shared.dns.write();
    s.mode = mode.into();
    s.note = note;
    s.since = Some(now_ms());
}

fn write(shared: &Shared, recs: &[Rec]) {
    if recs.is_empty() {
        return;
    }
    let procs: HashMap<u32, (String, Option<String>)> =
        shared.processes.read().iter().map(|p| (p.pid, (p.name.clone(), p.exe.clone()))).collect();
    let st = shared.store.lock();
    let Ok(tx) = st.conn.unchecked_transaction() else { return };
    let mut checks = Vec::with_capacity(recs.len());
    for r in recs {
        let (process, exe) = r.pid.and_then(|p| procs.get(&p).cloned()).map(|(n, e)| (Some(n), e)).unwrap_or((None, None));
        checks.push((r.name.clone(), r.status, r.pid, process.clone(), exe.clone()));
        let _ = st.conn.execute(
            "INSERT INTO dns_log (ts, name, qtype, status, pid, process, exe, results, source) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![r.ts, r.name, r.qtype, r.status, r.pid, process, exe, r.results, r.source],
        );
    }
    let _ = tx.commit();
    drop(st);
    shared.dns.write().logged += recs.len() as u64;
    for (name, status, pid, process, exe) in &checks {
        super::dnsrisk::check(shared, &super::dnsrisk::Query { name, status: *status, pid: *pid, process: process.as_deref(), exe: exe.as_deref() });
    }
}

// ------------------------------------------------------------------ ETW (elevated)

static TX: OnceLock<SyncSender<Rec>> = OnceLock::new();

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// EVENT_TRACE_PROPERTIES followed by room for the session name, 8-byte aligned.
fn props_buf(name_len: usize) -> Vec<u64> {
    let size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_len * 2 + 16;
    let mut buf = vec![0u64; size.div_ceil(8)];
    let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*p).Wnode.BufferSize = (buf.len() * 8) as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*p).Wnode.ClientContext = 2; // system time
        (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*p).FlushTimer = 1;
        (*p).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    }
    buf
}

/// Stop our ETW session (also one left behind by a crashed run). Errors are ignored.
pub fn stop_session() {
    let name = wide(SESSION);
    let mut buf = props_buf(name.len());
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

fn etw_start() -> Result<Receiver<Rec>, String> {
    let (tx, rx) = mpsc::sync_channel::<Rec>(8192);
    if TX.set(tx).is_err() {
        return Err("ikinci kez başlatılamaz".into());
    }
    stop_session();
    let name = wide(SESSION);
    let mut buf = props_buf(name.len());
    let mut handle = CONTROLTRACE_HANDLE::default();
    unsafe {
        let r = StartTraceW(&mut handle, PCWSTR(name.as_ptr()), buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
        if r != ERROR_SUCCESS {
            return Err(format!("StartTrace {}", r.0));
        }
        let r = EnableTraceEx2(
            handle,
            &DNS_CLIENT,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            0,
            0,
            0,
            None,
        );
        if r != ERROR_SUCCESS {
            stop_session();
            return Err(format!("EnableTrace {}", r.0));
        }
    }
    std::thread::Builder::new()
        .name("dnslog-etw".into())
        .spawn(move || {
            let mut name = wide(SESSION);
            let mut lf = EVENT_TRACE_LOGFILEW::default();
            lf.LoggerName = PWSTR(name.as_mut_ptr());
            lf.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            lf.Anonymous2.EventRecordCallback = Some(on_event);
            unsafe {
                let h = OpenTraceW(&mut lf);
                if h.Value == u64::MAX {
                    log::warn!("OpenTrace failed");
                    return;
                }
                let _ = ProcessTrace(&[h], None, None);
                let _ = CloseTrace(h);
            }
            // Dropping this thread's view of the session ends the drain loop via timeout check.
            log::warn!("DNS ETW session ended");
        })
        .map_err(|e| e.to_string())?;
    Ok(rx)
}

/// Read a NUL-terminated UTF-16 string from `b`, returning it and the bytes after it.
fn take_wstr(b: &[u8]) -> Option<(String, &[u8])> {
    let mut units = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let u = u16::from_le_bytes([b[i], b[i + 1]]);
        i += 2;
        if u == 0 {
            return Some((String::from_utf16_lossy(&units), &b[i..]));
        }
        units.push(u);
    }
    None
}

fn take_u32(b: &[u8]) -> Option<(u32, &[u8])> {
    Some((u32::from_le_bytes(b.get(..4)?.try_into().ok()?), &b[4..]))
}

/// Event 3008 payload: QueryName, QueryType u32, QueryOptions u64, QueryStatus u32, QueryResults.
fn parse_3008(b: &[u8]) -> Option<(String, u32, u32, String)> {
    let (name, rest) = take_wstr(b)?;
    let (qtype, rest) = take_u32(rest)?;
    let rest = rest.get(8..)?;
    let (status, rest) = take_u32(rest)?;
    let results = take_wstr(rest).map(|(s, _)| s).unwrap_or_default();
    Some((name, qtype, status, results))
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    let Some(r) = (unsafe { rec.as_ref() }) else { return };
    if r.EventHeader.ProviderId != DNS_CLIENT || r.EventHeader.EventDescriptor.Id != EV_QUERY_COMPLETED {
        return;
    }
    if r.UserData.is_null() || r.UserDataLength == 0 {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(r.UserData as *const u8, r.UserDataLength as usize) };
    let Some((name, qtype, status, results)) = parse_3008(data) else { return };
    if let Some(tx) = TX.get() {
        let _ = tx.try_send(Rec {
            ts: now_ms(),
            name,
            qtype,
            status: Some(status),
            pid: Some(r.EventHeader.ProcessId),
            results,
            source: "etw",
        });
    }
}

/// Batch-write ETW records; the same (process, name) is written at most once a minute.
fn etw_drain(shared: &Shared, rx: Receiver<Rec>) {
    let me = std::process::id();
    let mut recent: HashMap<(u32, String), i64> = HashMap::new();
    let mut batch = Vec::new();
    let mut last_flush = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(mut r) => {
                let pid = r.pid.unwrap_or(0);
                r.name = r.name.trim_end_matches('.').to_ascii_lowercase();
                if pid == me || r.qtype == QTYPE_PTR || r.name.is_empty() || is_reverse(&r.name) {
                    continue;
                }
                r.results = clean_results(&r.results);
                let k = (pid, r.name.clone());
                if recent.get(&k).is_some_and(|t| r.ts - t < 60_000) {
                    continue;
                }
                recent.insert(k, r.ts);
                batch.push(r);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        if last_flush.elapsed() >= Duration::from_secs(2) || batch.len() >= 500 {
            write(shared, &batch);
            batch.clear();
            last_flush = Instant::now();
            if recent.len() > 20_000 {
                let cut = now_ms() - 60_000;
                recent.retain(|_, t| *t >= cut);
            }
        }
    }
}

/// Reverse lookups (IP → name) — mostly our own hostname resolution, never interesting.
fn is_reverse(name: &str) -> bool {
    name.ends_with(".in-addr.arpa") || name.ends_with(".ip6.arpa")
}

/// "type:  5 x.example.net;::ffff:1.2.3.4;1.2.3.4;" → "x.example.net, 1.2.3.4"
fn clean_results(s: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for part in s.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let v = part.strip_prefix("type:").map(|r| r.trim().split_whitespace().nth(1).unwrap_or("")).unwrap_or(part);
        let v = v.strip_prefix("::ffff:").unwrap_or(v).trim_end_matches('.').to_string();
        if !v.is_empty() && !out.contains(&v) {
            out.push(v);
        }
    }
    out.join(", ")
}

// ------------------------------------------------------------------ DNS cache (standard user)

#[repr(C)]
struct CacheEntry {
    next: *mut CacheEntry,
    name: *mut u16,
    wtype: u16,
    data_len: u16,
    flags: u32,
}

type GetCacheFn = unsafe extern "system" fn(*mut *mut CacheEntry) -> i32;

/// Names currently in the resolver cache with their record type (undocumented but stable API).
fn cache_names() -> Result<Vec<(String, u16)>, String> {
    unsafe {
        let h = LoadLibraryW(w!("dnsapi.dll")).map_err(|e| e.message())?;
        let f = GetProcAddress(h, s!("DnsGetCacheDataTable")).ok_or("DnsGetCacheDataTable yok")?;
        let get: GetCacheFn = std::mem::transmute(f);
        let mut head: *mut CacheEntry = std::ptr::null_mut();
        if get(&mut head) == 0 {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            let e = &*cur;
            if !e.name.is_null() {
                let mut n = 0;
                while *e.name.add(n) != 0 && n < 512 {
                    n += 1;
                }
                out.push((String::from_utf16_lossy(std::slice::from_raw_parts(e.name, n)), e.wtype));
                DnsFree(Some(e.name as *const _), DnsFreeFlat);
            }
            let next = e.next;
            DnsFree(Some(cur as *const _), DnsFreeFlat);
            cur = next;
        }
        Ok(out)
    }
}

/// Addresses of a name that was just seen in the resolver cache. The system resolver answers
/// from that cache (the cache-only query flag returns "no records" on Windows 10, so it is
/// not used); only a name whose entry expired in the meantime goes out to the network.
fn cached_addrs(name: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let mut out: Vec<String> = (name, 0u16)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip().to_string()).collect())
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

fn cache_loop(shared: &Shared) {
    let mut present: std::collections::HashSet<String> = Default::default();
    let mut logged_at: HashMap<String, i64> = HashMap::new();
    loop {
        match cache_names() {
            Ok(entries) => {
                let mut by_name: HashMap<String, u16> = HashMap::new();
                for (n, t) in entries {
                    let n = n.trim_end_matches('.').to_ascii_lowercase();
                    if t as u32 == QTYPE_PTR || n.is_empty() || is_reverse(&n) {
                        continue;
                    }
                    let e = by_name.entry(n).or_insert(t);
                    if t == DNS_TYPE_A.0 {
                        *e = t;
                    }
                }
                let now = now_ms();
                let mut recs = Vec::new();
                for (name, t) in &by_name {
                    let fresh = !present.contains(name) && logged_at.get(name).is_none_or(|ts| now - ts > 600_000);
                    if !fresh {
                        continue;
                    }
                    logged_at.insert(name.clone(), now);
                    // Single-label names (wpad, printer) are LAN lookups; resolving them again
                    // would only send broadcast queries.
                    let ips = if name.contains('.') { cached_addrs(name) } else { vec![] };
                    recs.push(Rec {
                        ts: now,
                        name: name.clone(),
                        qtype: *t as u32,
                        status: None,
                        pid: attribute(shared, &ips),
                        results: ips.join(", "),
                        source: "cache",
                    });
                }
                present = by_name.into_keys().collect();
                write(shared, &recs);
                if logged_at.len() > 50_000 {
                    logged_at.retain(|_, t| now - *t < 3_600_000);
                }
            }
            Err(e) => {
                let mut s = shared.dns.write();
                s.mode = "off".into();
                s.note = Some(format!("DNS önbelleği okunamadı: {e}"));
                return;
            }
        }
        std::thread::sleep(Duration::from_secs(15));
    }
}

/// The process connected to one of these addresses right now (or in the last 10 minutes).
fn attribute(shared: &Shared, ips: &[String]) -> Option<u32> {
    if ips.is_empty() {
        return None;
    }
    if let Some(c) = shared.connections.read().iter().find(|c| c.remote_addr.as_ref().is_some_and(|r| ips.contains(r))) {
        return Some(c.pid);
    }
    let st = shared.store.lock();
    let since = now_ms() - 600_000;
    for ip in ips {
        let pid: Option<u32> = st
            .conn
            .query_row("SELECT pid FROM conn_history WHERE remote=?1 AND ts>=?2 ORDER BY ts DESC LIMIT 1", params![ip, since], |r| r.get(0))
            .ok();
        if pid.is_some() {
            return pid;
        }
    }
    None
}

// ------------------------------------------------------------------ queries

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRow {
    pub ts: i64,
    pub name: String,
    pub qtype: u32,
    pub status: Option<u32>,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub exe: Option<String>,
    pub results: String,
    pub source: String,
}

pub fn query(db: &rusqlite::Connection, search: Option<&str>, exe: Option<&str>, since: Option<i64>, limit: u32) -> rusqlite::Result<Vec<DnsRow>> {
    let like = search.filter(|s| !s.trim().is_empty()).map(|s| format!("%{}%", s.trim()));
    let mut st = db.prepare(
        "SELECT ts, name, qtype, status, pid, process, exe, results, source FROM dns_log
          WHERE name NOT LIKE '%.arpa'
            AND (?1 IS NULL OR name LIKE ?1 OR process LIKE ?1 OR results LIKE ?1)
            AND (?2 IS NULL OR exe = ?2 COLLATE NOCASE)
            AND (?3 IS NULL OR ts >= ?3)
          ORDER BY ts DESC LIMIT ?4",
    )?;
    let rows = st.query_map(params![like, exe, since, limit], |r| {
        Ok(DnsRow {
            ts: r.get(0)?,
            name: r.get(1)?,
            qtype: r.get(2)?,
            status: r.get(3)?,
            pid: r.get(4)?,
            process: r.get(5)?,
            exe: r.get(6)?,
            results: r.get(7)?,
            source: r.get(8)?,
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_completed_payload() {
        let mut b = Vec::new();
        for u in "example.com".encode_utf16().chain([0]) {
            b.extend(u.to_le_bytes());
        }
        b.extend(1u32.to_le_bytes());
        b.extend(0x2000u64.to_le_bytes());
        b.extend(0u32.to_le_bytes());
        for u in "type:  5 edge.example.net;::ffff:93.184.216.34;".encode_utf16().chain([0]) {
            b.extend(u.to_le_bytes());
        }
        let (n, t, s, r) = parse_3008(&b).unwrap();
        assert_eq!((n.as_str(), t, s), ("example.com", 1, 0));
        assert_eq!(clean_results(&r), "edge.example.net, 93.184.216.34");
        assert!(parse_3008(&b[..10]).is_none());
    }

    /// Reads the real cache many times: exercises the undocumented free path.
    #[test]
    fn live_cache_read_is_stable() {
        let _ = std::net::ToSocketAddrs::to_socket_addrs(&("example.com", 80));
        for _ in 0..200 {
            cache_names().expect("cache");
        }
        let names = cache_names().unwrap();
        assert!(!names.is_empty());
        let has = names.iter().any(|(n, _)| n.eq_ignore_ascii_case("example.com"));
        if has {
            assert!(!cached_addrs("example.com").is_empty());
        }
    }
}
