// Mirrors src-tauri/src/model.rs (serde camelCase).

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export const SEVERITIES: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

export interface DiskInfo {
  mount: string;
  label: string;
  fs: string;
  total: number;
  available: number;
}

export interface SystemMetrics {
  ts: number;
  cpu: number;
  cpuCores: number[];
  memUsed: number;
  memTotal: number;
  swapUsed: number;
  swapTotal: number;
  disks: DiskInfo[];
  netRxRate: number;
  netTxRate: number;
  processCount: number;
  uptime: number;
}

export interface HostInfo {
  hostname: string;
  osName: string;
  osVersion: string;
  kernel: string;
  cpuBrand: string;
  cpuCount: number;
  memTotal: number;
  elevated: boolean;
  bootTime: number;
  appVersion: string;
  dataDir: string;
}

export type SignatureState = "pending" | "signed" | "unsigned" | "invalid" | "unknown";

export interface SignatureInfo {
  state: SignatureState;
  publisher: string | null;
}

export interface ProcessInfo {
  pid: number;
  ppid: number | null;
  name: string;
  exe: string | null;
  cmd: string | null;
  cpu: number;
  memory: number;
  startTime: number;
  user: string | null;
  signature: SignatureInfo;
  connections: number;
  critical: boolean;
  risk: Severity | null;
}

export type AddrScope = "loopback" | "private" | "public" | "unspecified";

export interface ConnectionInfo {
  id: string;
  protocol: "tcp" | "udp";
  ipv6: boolean;
  localAddr: string;
  localPort: number;
  remoteAddr: string | null;
  remotePort: number | null;
  state: string;
  pid: number;
  processName: string | null;
  started: number;
  scope: AddrScope;
  hostname: string | null;
  country: string | null;
  asn: string | null;
  risk: Severity | null;
}

export interface SecurityEvent {
  id: number;
  ts: number;
  kind: string;
  severity: Severity;
  title: string;
  detail: string;
  subject: string | null;
  data: Record<string, unknown>;
}

export interface Signal {
  rule: string;
  label: string;
  weight: number;
  evidence: string;
}

export interface Finding {
  key: string;
  entityKind: string;
  entity: string;
  title: string;
  severity: Severity;
  score: number;
  signals: Signal[];
  firstSeen: number;
  lastSeen: number;
  pid: number | null;
  pids: number[];
  status: string;
}

export interface Snapshot {
  host: HostInfo;
  metrics: SystemMetrics | null;
  processes: ProcessInfo[];
  connections: ConnectionInfo[];
  findings: Finding[];
}

export interface KillResult {
  ok: boolean;
  needs: "confirm" | "admin" | null;
  message: string;
}

export interface EventQuery {
  since?: number;
  until?: number;
  kinds?: string[];
  minSeverity?: Severity;
  search?: string;
  limit?: number;
}

export interface GeoStatus {
  countryDb: boolean;
  asnDb: boolean;
  built: string | null;
}

export interface ConnHistoryRow {
  ts: number;
  pid: number;
  process: string | null;
  exe: string | null;
  remote: string;
  port: number;
  hostname: string | null;
  country: string | null;
  asn: string | null;
}
