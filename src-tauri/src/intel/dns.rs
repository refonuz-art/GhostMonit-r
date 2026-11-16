//! Reverse DNS with a background worker and an in-memory cache.
//! Uses the system resolver (getnameinfo), so it honours the OS DNS cache and hosts file.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;

use parking_lot::Mutex;

#[derive(Clone)]
pub struct ReverseDns {
    cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    queued: Arc<Mutex<HashSet<IpAddr>>>,
    tx: Sender<IpAddr>,
}

impl ReverseDns {
    pub fn new() -> Self {
        let (tx, rx) = channel::<IpAddr>();
        let cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>> = Default::default();
        let queued: Arc<Mutex<HashSet<IpAddr>>> = Default::default();
        let (c2, q2) = (cache.clone(), queued.clone());
        std::thread::Builder::new()
            .name("rdns".into())
            .spawn(move || {
                while let Ok(ip) = rx.recv() {
                    let name = dns_lookup::lookup_addr(&ip)
                        .ok()
                        // getnameinfo echoes the address back when no PTR exists
                        .filter(|n| n.parse::<IpAddr>().is_err());
                    c2.lock().insert(ip, name);
                    q2.lock().remove(&ip);
                }
            })
            .expect("spawn rdns");
        Self { cache, queued, tx }
    }

    /// Returns a cached name, or None and schedules a lookup.
    pub fn get(&self, ip: IpAddr) -> Option<String> {
        if let Some(v) = self.cache.lock().get(&ip) {
            return v.clone();
        }
        if self.queued.lock().insert(ip) {
            let _ = self.tx.send(ip);
        }
        None
    }

    /// Blocking lookup for explicit user queries (terminal "ip" command).
    pub fn resolve_now(&self, ip: IpAddr) -> Option<String> {
        if let Some(v) = self.cache.lock().get(&ip) {
            return v.clone();
        }
        let name = dns_lookup::lookup_addr(&ip).ok().filter(|n| n.parse::<IpAddr>().is_err());
        self.cache.lock().insert(ip, name.clone());
        name
    }
}
