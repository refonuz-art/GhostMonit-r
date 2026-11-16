//! Shared data model sent over IPC. Field names are camelCase on the TS side.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s {
            "LOW" => Severity::Low,
            "MEDIUM" => Severity::Medium,
            "HIGH" => Severity::High,
            "CRITICAL" => Severity::Critical,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemMetrics {
    pub ts: i64,
    pub cpu: f32,
    pub cpu_cores: Vec<f32>,
    pub mem_used: u64,
    pub mem_total: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub disks: Vec<DiskInfo>,
    pub net_rx_rate: u64,
    pub net_tx_rate: u64,
    pub process_count: usize,
    pub uptime: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskInfo {
    pub mount: String,
    pub label: String,
    pub fs: String,
    pub total: u64,
    pub available: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel: String,
    pub cpu_brand: String,
    pub cpu_count: usize,
    pub mem_total: u64,
    pub elevated: bool,
    pub boot_time: u64,
    pub app_version: String,
    pub data_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SignatureState {
    /// Not checked yet (verification runs lazily in background).
    Pending,
    Signed,
    Unsigned,
    /// Signature present but invalid / untrusted / expired chain.
    Invalid,
    /// File not accessible (protected process or missing path).
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    pub state: SignatureState,
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: Option<String>,
    pub cmd: Option<String>,
    pub cpu: f32,
    pub memory: u64,
    pub start_time: u64,
    pub user: Option<String>,
    pub signature: SignatureInfo,
    pub connections: u32,
    pub critical: bool,
    /// Highest severity of active findings for this pid (None = clean).
    pub risk: Option<Severity>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    pub id: String,
    pub protocol: Protocol,
    pub ipv6: bool,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub pid: u32,
    pub process_name: Option<String>,
    /// Unix ms. From the kernel's TCP create timestamp when available, else first-seen.
    pub started: i64,
    pub scope: AddrScope,
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub risk: Option<Severity>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AddrScope {
    Loopback,
    Private,
    Public,
    Unspecified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub subject: Option<String>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signal {
    pub rule: String,
    pub label: String,
    pub weight: u32,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable key: "<entity-kind>:<entity-id>"
    pub key: String,
    pub entity_kind: String,
    pub entity: String,
    pub title: String,
    pub severity: Severity,
    pub score: u32,
    pub signals: Vec<Signal>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub pid: Option<u32>,
    /// All running processes that share this finding's key.
    #[serde(default)]
    pub pids: Vec<u32>,
    pub status: String,
}
