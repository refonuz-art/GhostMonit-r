//! Signature results cached per path (+size+mtime). Verification is slow (catalog lookup),
//! so it runs on a single background worker; callers get `Pending` until it is done.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;

use crate::model::{SignatureInfo, SignatureState};
use crate::winapi::signature;

#[derive(Clone)]
struct Entry {
    stamp: (u64, Option<SystemTime>),
    info: SignatureInfo,
}

#[derive(Clone)]
pub struct SigCache {
    map: Arc<Mutex<HashMap<String, Entry>>>,
    queued: Arc<Mutex<HashSet<String>>>,
    tx: Sender<String>,
}

fn stamp(path: &str) -> Option<(u64, Option<SystemTime>)> {
    std::fs::metadata(path).ok().map(|m| (m.len(), m.modified().ok()))
}

impl SigCache {
    pub fn new() -> Self {
        let (tx, rx) = channel::<String>();
        let map: Arc<Mutex<HashMap<String, Entry>>> = Default::default();
        let queued: Arc<Mutex<HashSet<String>>> = Default::default();
        let (m2, q2) = (map.clone(), queued.clone());
        std::thread::Builder::new()
            .name("sig-worker".into())
            .spawn(move || {
                while let Ok(path) = rx.recv() {
                    let info = signature::verify(&path);
                    let st = stamp(&path).unwrap_or((0, None));
                    m2.lock().insert(path.clone(), Entry { stamp: st, info });
                    q2.lock().remove(&path);
                }
            })
            .expect("spawn sig worker");
        Self { map, queued, tx }
    }

    /// Non-blocking. Returns the cached result or `Pending` and schedules a check.
    pub fn get_or_queue(&self, path: &str) -> SignatureInfo {
        if let Some(e) = self.map.lock().get(path) {
            return e.info.clone();
        }
        self.queue(path);
        SignatureInfo { state: SignatureState::Pending, publisher: None }
    }

    fn queue(&self, path: &str) {
        if self.queued.lock().insert(path.to_string()) {
            let _ = self.tx.send(path.to_string());
        }
    }

    /// Blocking verify (used by File Intelligence for an explicit user request).
    pub fn verify_now(&self, path: &str) -> SignatureInfo {
        let st = stamp(path);
        if let (Some(st), Some(e)) = (st, self.map.lock().get(path)) {
            if e.stamp == st {
                return e.info.clone();
            }
        }
        let info = signature::verify(path);
        self.map
            .lock()
            .insert(path.to_string(), Entry { stamp: st.unwrap_or((0, None)), info: info.clone() });
        info
    }

    /// Drop entries whose file changed on disk so they are re-verified.
    pub fn revalidate(&self) {
        let stale: Vec<String> = self
            .map
            .lock()
            .iter()
            .filter(|(p, e)| stamp(p).map(|s| s != e.stamp).unwrap_or(false))
            .map(|(p, _)| p.clone())
            .collect();
        let mut m = self.map.lock();
        for p in stale {
            m.remove(&p);
        }
    }
}
