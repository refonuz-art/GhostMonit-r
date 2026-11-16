import type { ConnectionInfo, Finding, Severity } from "../ipc/types";
import { SEVERITIES } from "../ipc/types";

export interface SecurityLevel {
  severity: Severity | null;
  word: string;
  note: string;
  /** 0..100, 100 = no active signals */
  index: number;
  tone: "phosphor" | "arc" | "warn" | "high" | "bad";
}

/** Security posture derived only from active findings — no invented inputs. */
export function securityLevel(findings: Finding[]): SecurityLevel {
  const active = findings.filter((f) => f.severity !== "INFO");
  const top = active.reduce<Severity | null>(
    (acc, f) => (acc === null || SEVERITIES.indexOf(f.severity) > SEVERITIES.indexOf(acc) ? f.severity : acc),
    null,
  );
  // Each finding costs points by severity; weak signals barely move the index.
  const COST: Record<Severity, number> = { INFO: 0, LOW: 2, MEDIUM: 8, HIGH: 20, CRITICAL: 45 };
  const load = active.reduce((s, f) => s + COST[f.severity], 0);
  const index = Math.max(0, 100 - Math.min(100, load));
  switch (top) {
    case "CRITICAL":
      return { severity: top, word: "Kritik", note: "Birden fazla bağımsız sinyal aynı öğeyi işaret ediyor", index, tone: "bad" };
    case "HIGH":
      return { severity: top, word: "Yüksek risk", note: "İncelenmesi gereken güçlü bulgular var", index, tone: "high" };
    case "MEDIUM":
      return { severity: top, word: "Dikkat", note: "Şüpheli davranış izleniyor", index, tone: "warn" };
    case "LOW":
      return { severity: top, word: "İzleniyor", note: "Zayıf sinyaller var, tek başına tehdit değil", index, tone: "arc" };
    default:
      return { severity: null, word: "Temiz", note: "Etkin kurallar şüpheli davranış görmüyor", index, tone: "phosphor" };
  }
}

export function topSeverity(findings: Finding[]): Severity | null {
  let top: Severity | null = null;
  for (const f of findings) {
    if (f.severity === "INFO") continue;
    if (top === null || SEVERITIES.indexOf(f.severity) > SEVERITIES.indexOf(top)) top = f.severity;
  }
  return top;
}

export function isListening(c: ConnectionInfo) {
  return c.protocol === "tcp" && c.state === "LISTEN";
}

export function openPorts(conns: ConnectionInfo[]) {
  const seen = new Map<string, ConnectionInfo>();
  for (const c of conns) {
    if (!isListening(c)) continue;
    const k = `${c.localPort}`;
    if (!seen.has(k) || seen.get(k)!.scope === "loopback") seen.set(k, c);
  }
  return [...seen.values()].sort((a, b) => a.localPort - b.localPort);
}

export function activeRemote(conns: ConnectionInfo[]) {
  return conns.filter((c) => c.remoteAddr && c.state === "ESTABLISHED" && c.scope !== "loopback");
}
