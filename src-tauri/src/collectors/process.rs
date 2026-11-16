use std::collections::HashMap;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

use crate::model::{ProcessInfo, SignatureInfo, SignatureState};
use crate::sigcache::SigCache;

/// Processes whose termination destabilises or crashes Windows.
pub const CRITICAL_NAMES: &[&str] = &[
    "system", "idle", "system idle process", "registry", "memory compression", "smss.exe",
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "svchost.exe", "fontdrvhost.exe", "dwm.exe", "secure system", "lsm.exe", "spoolsv.exe",
    "msmpeng.exe", "sgrmbroker.exe", "searchindexer.exe",
];

pub fn is_critical(pid: u32, name: &str) -> bool {
    if pid <= 4 {
        return true;
    }
    let n = name.to_ascii_lowercase();
    CRITICAL_NAMES.contains(&n.as_str())
}

pub fn refresh(sys: &mut System) {
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet),
    );
}

pub fn collect(
    sys: &System,
    users: &Users,
    sigs: &SigCache,
    conn_counts: &HashMap<u32, u32>,
) -> Vec<ProcessInfo> {
    let ncpu = sys.cpus().len().max(1) as f32;
    let own = std::process::id();
    sys.processes()
        .values()
        .map(|p| {
            let pid = p.pid().as_u32();
            let name = p.name().to_string_lossy().into_owned();
            let exe = p.exe().map(|e| e.to_string_lossy().into_owned()).filter(|s| !s.is_empty());
            let cmd = {
                let parts: Vec<String> = p.cmd().iter().map(|c| c.to_string_lossy().into_owned()).collect();
                (!parts.is_empty()).then(|| parts.join(" "))
            };
            let signature = match &exe {
                Some(path) => sigs.get_or_queue(path),
                None => SignatureInfo { state: SignatureState::Unknown, publisher: None },
            };
            ProcessInfo {
                pid,
                ppid: p.parent().map(|pp| pp.as_u32()),
                critical: is_critical(pid, &name) || pid == own,
                name,
                exe,
                cmd,
                cpu: p.cpu_usage() / ncpu,
                memory: p.memory(),
                start_time: p.start_time(),
                user: p.user_id().and_then(|u| users.get_user_by_id(u)).map(|u| u.name().to_string()),
                signature,
                connections: conn_counts.get(&pid).copied().unwrap_or(0),
                risk: None,
            }
        })
        .collect()
}
