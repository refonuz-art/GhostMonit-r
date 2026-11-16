import { invoke } from "@tauri-apps/api/core";
import type { Severity, Signal } from "./types";

export interface AvProduct {
  name: string;
  enabled: boolean;
  upToDate: boolean;
}
export interface SecurityStatus {
  checked: number;
  defenderAvailable: boolean;
  realtime: boolean | null;
  behavior: boolean | null;
  tamper: boolean | null;
  signatureAgeDays: number | null;
  quickScanAgeDays: number | null;
  mode: string | null;
  exclusions: string[] | null;
  products: AvProduct[];
  firewall: { name: string; enabled: boolean }[];
  lastUpdate: string | null;
  lastUpdateId: string | null;
  signals: Signal[];
  error: string | null;
}
export interface NetConf {
  hosts: { ip: string; host: string; risk: string | null }[];
  hostsPath: string;
  dns: { adapter: string; server: string; provider: string | null }[];
  proxy: { enabled: boolean; server: string | null; pacUrl: string | null };
  signals: Signal[];
}
export interface Extension {
  key: string;
  browser: string;
  profile: string;
  id: string;
  name: string;
  version: string;
  enabled: boolean;
  fromStore: boolean;
  permissions: string[];
  path: string;
  signals: Signal[];
  severity: Severity;
}
export interface LanDevice {
  ip: string;
  mac: string;
  vendor: string | null;
  name: string | null;
  firstSeen: number;
  lastSeen: number;
  online: boolean;
  gateway: boolean;
}
export interface CanaryStatus {
  enabled: boolean;
  files: string[];
  watchedFolders: string[];
  tripped: number | null;
  lastAlert: string | null;
}
export interface EventLogStatus {
  lastCheck: number | null;
  channels: { name: string; label: string; readable: boolean; needsAdmin: boolean }[];
}
export type CheckStatus = "ok" | "warn" | "bad" | "unknown";
export interface HealthCheck {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
  weight: number;
  fix: string | null;
}
export interface HealthReport {
  score: number;
  grade: string;
  computed: number;
  checks: HealthCheck[];
}
export interface GuardState {
  defender: SecurityStatus | null;
  netconf: NetConf | null;
  extensions: Extension[];
  extensionsScanned: number | null;
  lan: LanDevice[];
  lanScanned: number | null;
  canary: CanaryStatus;
  eventlog: EventLogStatus;
  health: HealthReport | null;
}
export interface BlockRule {
  name: string;
  kind: "program" | "ip";
  target: string;
  created: number;
}
export interface QItem {
  id: number;
  original: string;
  sha256: string;
  size: number;
  reason: string;
  createdAt: number;
}
export interface ProcUsage {
  pid: number;
  name: string;
  exe: string | null;
  bytesIn: number;
  bytesOut: number;
  rateIn: number;
  rateOut: number;
  connections: number;
}
export interface NetUsage {
  available: boolean;
  reason: string | null;
  since: number | null;
  sampled: number | null;
  processes: ProcUsage[];
}

export type GuardCheck = "defender" | "browser" | "netconf" | "lan" | "eventlog" | "health";

export const guard = {
  state: () => invoke<GuardState>("guard_state"),
  refresh: (what: GuardCheck) => invoke<GuardState>("guard_refresh", { what }),
  fwRules: () => invoke<BlockRule[]>("fw_rules"),
  block: (kind: "program" | "ip", target: string) => invoke<BlockRule>("fw_block", { kind, target }),
  unblock: (name: string) => invoke<void>("fw_unblock", { name }),
  quarantine: () => invoke<QItem[]>("quarantine_list"),
  quarantineAdd: (path: string, reason?: string) => invoke<QItem>("quarantine_add", { path, reason }),
  quarantineRestore: (id: number) => invoke<string>("quarantine_restore", { id }),
  quarantineDelete: (id: number) => invoke<void>("quarantine_delete", { id }),
  remoteStatus: () => invoke<{ telegram: boolean; discord: boolean }>("remote_status"),
  setTelegram: (token: string | null, chat: string | null) => invoke<void>("remote_set_telegram", { token, chat }),
  setDiscord: (url: string | null) => invoke<void>("remote_set_discord", { url }),
  remoteTest: () => invoke<number>("remote_test"),
  lanSweep: () => invoke<number>("lan_sweep"),
  netUsage: () => invoke<NetUsage>("net_usage"),
  suspend: (pid: number, suspend: boolean) => invoke<string>("suspend_process", { pid, suspend }),
};
