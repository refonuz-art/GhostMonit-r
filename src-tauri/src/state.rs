use std::sync::atomic::AtomicBool;

use parking_lot::{Mutex, RwLock};

use crate::model::{ConnectionInfo, Finding, HostInfo, ProcessInfo, SystemMetrics};
use crate::collectors::startup::StartupItem;
use crate::intel::{dns::ReverseDns, geo::Geo, hashdb::ExeHashes};
use crate::sigcache::SigCache;
use crate::store::Store;

pub struct Shared {
    pub host: RwLock<HostInfo>,
    pub metrics: RwLock<Option<SystemMetrics>>,
    pub processes: RwLock<Vec<ProcessInfo>>,
    pub connections: RwLock<Vec<ConnectionInfo>>,
    pub findings: RwLock<Vec<Finding>>,
    pub store: Mutex<Store>,
    pub sigs: SigCache,
    pub rdns: ReverseDns,
    pub geo: Geo,
    pub exe_hashes: ExeHashes,
    pub startup: RwLock<Vec<StartupItem>>,
    pub startup_findings: RwLock<Vec<Finding>>,
    pub startup_scanned_at: RwLock<Option<i64>>,
    pub startup_rescan: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    /// Window hidden/minimised → monitor slows its cadence.
    pub background: AtomicBool,
    pub settings: RwLock<crate::settings::AppSettings>,
    pub notifier: Mutex<crate::shell::NotifyState>,
    /// Findings from the file and drive watchers, merged into the monitor's list.
    pub watch_findings: RwLock<Vec<Finding>>,
    pub auto_scans: RwLock<Vec<crate::watchers::AutoScan>>,
    pub drives: RwLock<Vec<crate::watchers::DriveInfo>>,
    pub guard: RwLock<crate::guard::GuardState>,
    pub net_usage: RwLock<crate::guard::netstats::NetUsage>,
}
