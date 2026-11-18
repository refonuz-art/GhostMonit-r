// 0.5: incident response, user rules, DNS history, process time machine, weekly diff.
import { invoke } from "@tauri-apps/api/core";
import type { Severity } from "./types";

export interface ProcRun {
  id: number;
  pid: number;
  ppid: number | null;
  name: string;
  exe: string | null;
  cmd: string | null;
  user: string | null;
  sigState: "pending" | "signed" | "unsigned" | "invalid" | "unknown";
  publisher: string | null;
  started: number;
  ended: number | null;
  endedApprox: boolean;
}

export interface IncidentContext {
  key: string;
  path: string | null;
  fileExists: boolean;
  running: { pid: number; name: string; critical: boolean }[];
  blockedBy: string | null;
  quarantined: boolean;
  startup: { id: string; kind: string; name: string; location: string; command: string }[];
  remotes: { remote: string; port: number; hostname: string | null; country: string | null; last: number; count: number }[];
  dns: { name: string; last: number; count: number }[];
  lineage: ProcRun[];
  runs: number;
  firstRun: number | null;
}

export type RuleAction = "alert" | "ignore";
export type RuleSigner = "any" | "signed" | "unsigned" | "invalid";

export interface UserRule {
  id: string;
  name: string;
  enabled: boolean;
  action: RuleAction;
  severity: Severity;
  namePat: string;
  pathPat: string;
  parentPat: string;
  cmdContains: string;
  signer: RuleSigner;
  publisherContains: string;
  internet: boolean;
  remotePorts: string;
  listens: boolean;
  note: string;
}

export interface RuleMatch {
  pid: number;
  name: string;
  exe: string | null;
  evidence: string;
}

export interface DnsStatus {
  mode: "etw" | "cache" | "off" | "";
  note: string | null;
  since: number | null;
  logged: number;
}

export interface DnsRow {
  ts: number;
  name: string;
  qtype: number;
  status: number | null;
  pid: number | null;
  process: string | null;
  exe: string | null;
  results: string;
  source: "etw" | "cache";
}

export interface WeeklyItem {
  ts: number;
  title: string;
  detail: string;
  severity: Severity | null;
}
export interface WeeklySection {
  id: string;
  title: string;
  now: number;
  prev: number;
  items: WeeklyItem[];
  note: string | null;
}
export interface WeeklyDiff {
  since: number;
  until: number;
  health: {
    now: number | null;
    nowDay: string | null;
    then: number | null;
    thenDay: string | null;
    changed: { label: string; from: string; to: string }[];
  };
  sections: WeeklySection[];
}

export const v5 = {
  incident: (key: string) => invoke<IncidentContext>("incident_context", { key }),
  rules: () => invoke<UserRule[]>("user_rules_get"),
  saveRules: (rules: UserRule[]) => invoke<void>("user_rules_save", { rules }),
  testRule: (rule: UserRule) => invoke<RuleMatch[]>("user_rule_test", { rule }),
  dnsStatus: () => invoke<DnsStatus>("dns_status"),
  dnsLog: (search?: string, exe?: string, since?: number, limit?: number) =>
    invoke<DnsRow[]>("dns_log", { search, exe, since, limit }),
  procAt: (ts: number) => invoke<{ ts: number; earliest: number | null; runs: ProcRun[] }>("proc_at", { ts }),
  procChanges: (since: number, until: number, limit?: number) => invoke<ProcRun[]>("proc_changes", { since, until, limit }),
  procLineage: (pid: number, started: number) => invoke<ProcRun[]>("proc_lineage", { pid, started }),
  weekly: () => invoke<WeeklyDiff>("weekly_diff"),
  traces: (exe: string, since: number, until: number) =>
    invoke<{ remotes: IncidentContext["remotes"]; dns: IncidentContext["dns"] }>("proc_traces", { exe, since, until }),
  weeklyToPhone: () => invoke<string>("remote_weekly_now"),
};

export const DNS_TYPE: Record<number, string> = { 1: "A", 5: "CNAME", 28: "AAAA", 33: "SRV", 16: "TXT", 15: "MX", 65: "HTTPS", 6: "SOA", 2: "NS" };

/** Windows DNS status codes worth naming. */
export function dnsStatusText(s: number | null): string | null {
  if (s == null || s === 0) return null;
  if (s === 9003) return "alan adı yok";
  if (s === 9501 || s === 9701) return "kayıt yok";
  if (s === 1460) return "zaman aşımı";
  if (s === 9002) return "sunucu hatası";
  return `hata ${s}`;
}

export function newRule(): UserRule {
  return {
    id: (crypto.randomUUID?.() ?? `r${Date.now()}${Math.random().toString(16).slice(2)}`).replace(/[^a-zA-Z0-9-]/g, ""),
    name: "",
    enabled: true,
    action: "alert",
    severity: "MEDIUM",
    namePat: "",
    pathPat: "",
    parentPat: "",
    cmdContains: "",
    signer: "any",
    publisherContains: "",
    internet: false,
    remotePorts: "",
    listens: false,
    note: "",
  };
}
