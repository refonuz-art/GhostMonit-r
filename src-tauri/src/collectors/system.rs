use std::time::Instant;

use sysinfo::{Disks, Networks, System};

use crate::model::{DiskInfo, HostInfo, SystemMetrics};

pub struct SystemCollector {
    networks: Networks,
    disks: Disks,
    last_net: Instant,
    disk_tick: u32,
}

impl SystemCollector {
    pub fn new() -> Result<Self, sysinfo::Error> {
        Ok(Self {
            networks: Networks::new_with_refreshed_list()?,
            disks: Disks::new_with_refreshed_list()?,
            last_net: Instant::now(),
            disk_tick: 0,
        })
    }

    /// `sys` must have had refresh_cpu_usage / refresh_memory called by the caller.
    pub fn collect(&mut self, sys: &System, process_count: usize) -> SystemMetrics {
        let elapsed = self.last_net.elapsed().as_secs_f64().max(0.001);
        self.networks.refresh(true);
        self.last_net = Instant::now();
        let (mut rx, mut tx) = (0u64, 0u64);
        for (name, data) in self.networks.iter() {
            // Loopback / pseudo adapters inflate totals.
            let n = name.to_string_lossy().to_ascii_lowercase();
            if n.contains("loopback") || n.contains("isatap") || n.contains("teredo") {
                continue;
            }
            rx += data.received();
            tx += data.transmitted();
        }

        // Disk free space changes slowly; refresh every 10th tick.
        self.disk_tick = self.disk_tick.wrapping_add(1);
        if self.disk_tick % 10 == 1 {
            self.disks.refresh(true);
        }

        SystemMetrics {
            ts: chrono::Utc::now().timestamp_millis(),
            cpu: sys.global_cpu_usage(),
            cpu_cores: sys.cpus().iter().map(|c| c.usage()).collect(),
            mem_used: sys.used_memory(),
            mem_total: sys.total_memory(),
            swap_used: sys.used_swap(),
            swap_total: sys.total_swap(),
            disks: self
                .disks
                .iter()
                .map(|d| DiskInfo {
                    mount: d.mount_point().to_string_lossy().into_owned(),
                    label: d.name().to_string_lossy().into_owned(),
                    fs: d.file_system().to_string_lossy().into_owned(),
                    total: d.total_space(),
                    available: d.available_space(),
                })
                .collect(),
            net_rx_rate: (rx as f64 / elapsed) as u64,
            net_tx_rate: (tx as f64 / elapsed) as u64,
            process_count,
            uptime: System::uptime().unwrap_or(0),
        }
    }
}

pub fn host_info(sys: &System, elevated: bool, data_dir: &str) -> HostInfo {
    HostInfo {
        hostname: System::host_name().unwrap_or_default(),
        os_name: System::long_os_version().or_else(|_| System::name()).unwrap_or_else(|_| "Windows".into()),
        os_version: System::os_version().unwrap_or_default(),
        kernel: System::kernel_version().unwrap_or_default(),
        cpu_brand: sys.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_default(),
        cpu_count: sys.cpus().len(),
        mem_total: sys.total_memory(),
        elevated,
        boot_time: System::boot_time().unwrap_or(0),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        data_dir: data_dir.to_string(),
    }
}
