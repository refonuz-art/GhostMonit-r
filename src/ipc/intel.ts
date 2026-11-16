// Types + calls for Phase 8 backends (commands_intel.rs).
import { invoke } from "@tauri-apps/api/core";
import type { ConnectionInfo, Finding, HostInfo, SecurityEvent, Severity, Signal, SignatureInfo } from "./types";

export interface Motw {
  zone: number;
  zoneName: string;
  hostUrl: string | null;
  referrerUrl: string | null;
}

export interface FileReport {
  path: string;
  name: string;
  size: number;
  created: number | null;
  modified: number | null;
  accessed: number | null;
  sha256: string;
  sha1: string;
  md5: string;
  kind: string;
  detail: string | null;
  extension: string;
  signature: SignatureInfo;
  motw: Motw | null;
  knownBad: string | null;
  signals: Signal[];
  score: number;
  severity: Severity;
}

export interface AutoScan {
  ts: number;
  origin: string;
  report: FileReport;
}

export interface DriveInfo {
  letter: string;
  kind: string;
  label: string;
  fs: string;
  size: number;
  since: number;
  autorun: string | null;
  rootExecutables: string[];
  severity: Severity;
}

export interface FeedResult {
  added: number;
  seen: number;
  total: number;
}

export interface HashDbStats {
  total: number;
  sources: [string, number][];
}

export interface Reputation {
  provider: string;
  found: boolean;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  label: string | null;
  link: string;
}

export interface StartupItem {
  id: string;
  kind: "registry" | "winlogon" | "folder" | "service" | "task";
  name: string;
  command: string;
  location: string;
  image: string | null;
  imageExists: boolean;
  enabled: boolean;
  start: string | null;
  state: string | null;
  account: string | null;
  author: string | null;
  signature: SignatureInfo | null;
  firstSeen: number;
  risk: Severity | null;
}

export interface IpInfo {
  ip: string;
  scope: string;
  hostname: string | null;
  country: string | null;
  asn: string | null;
  live: ConnectionInfo[];
  seenCount: number;
  firstSeen: number | null;
  lastSeen: number | null;
  processes: string | null;
}

export interface ReportData {
  kind: "daily" | "weekly";
  title: string;
  generatedAt: number;
  since: number;
  until: number;
  host: HostInfo;
  topSeverity: Severity | null;
  totalEvents: number;
  bySeverity: [string, number][];
  byKind: [string, number][];
  findings: Finding[];
  topProcesses: [string, number][];
  topRemotes: { remote: string; hostname: string | null; country: string | null; asn: string | null; count: number; processes: string }[];
  newRemoteHosts: number;
  startupEvents: SecurityEvent[];
  notableEvents: SecurityEvent[];
  openPorts: { port: number; protocol: string; bind: string; process: string }[];
  days: { day: string; events: number; threats: number; newRemotes: number }[];
}

export const intel = {
  autoScans: () => invoke<AutoScan[]>("auto_scans"),
  drives: () => invoke<DriveInfo[]>("drives"),
  abuseHasKey: () => invoke<boolean>("abuse_has_key"),
  abuseSetKey: (key: string | null) => invoke<void>("abuse_set_key", { key }),
  feedUpdateNow: () => invoke<FeedResult>("feed_update_now"),
  analyzeFile: (path: string) => invoke<FileReport>("analyze_file", { path }),
  hashdbStats: () => invoke<HashDbStats>("hashdb_stats"),
  hashdbImport: (path: string) => invoke<{ added: number; seen: number }>("hashdb_import", { path }),
  hashdbClear: () => invoke<number>("hashdb_clear"),
  vtHasKey: () => invoke<boolean>("vt_has_key"),
  vtSetKey: (key: string | null) => invoke<void>("vt_set_key", { key }),
  vtLookup: (sha256: string) => invoke<Reputation>("vt_lookup", { sha256 }),
  startupItems: () => invoke<{ items: StartupItem[]; scannedAt: number | null }>("startup_items"),
  rescanStartup: () => invoke<void>("rescan_startup"),
  ipInfo: (ip: string) => invoke<IpInfo>("ip_info", { ip }),
  buildReport: (kind: string, since?: number, until?: number) => invoke<ReportData>("build_report", { kind, since, until }),
  exportReport: (kind: string, format: "json" | "pdf", path: string, since?: number, until?: number) =>
    invoke<string>("export_report", { kind, format, path, since, until }),
};
