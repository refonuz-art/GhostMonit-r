import { create } from "zustand";
import type {
  ConnectionInfo,
  Finding,
  HostInfo,
  ProcessInfo,
  SecurityEvent,
  SystemMetrics,
} from "../ipc/types";

export type ModuleId =
  | "command"
  | "process"
  | "network"
  | "threat"
  | "file"
  | "startup"
  | "timeline"
  | "terminal"
  | "report"
  | "health"
  | "settings"
  | "ayla";

const HISTORY = 180; // 3 minutes at 1 Hz

export interface Series {
  t: number[];
  cpu: number[];
  mem: number[];
  rx: number[];
  tx: number[];
}

interface GhostState {
  ready: boolean;
  host: HostInfo | null;
  metrics: SystemMetrics | null;
  series: Series;
  processes: ProcessInfo[];
  connections: ConnectionInfo[];
  findings: Finding[];
  liveEvents: SecurityEvent[];
  module: ModuleId;
  focusPid: number | null;
  processQuery: string;
  toast: { text: string; tone: "ok" | "warn" | "bad" } | null;
  /** Tab the Sağlık screen opens on next (set by the assistant). */
  healthTab: string | null;

  setModule: (m: ModuleId) => void;
  focusProcess: (pid: number | null) => void;
  searchProcesses: (q: string) => void;
  pushMetrics: (m: SystemMetrics) => void;
  pushEvent: (e: SecurityEvent) => void;
  notify: (text: string, tone?: "ok" | "warn" | "bad") => void;
}

const empty: Series = { t: [], cpu: [], mem: [], rx: [], tx: [] };

function append(arr: number[], v: number) {
  const next = arr.length >= HISTORY ? arr.slice(1) : arr.slice();
  next.push(v);
  return next;
}

let toastTimer: number | undefined;

export const useGhost = create<GhostState>((set) => ({
  ready: false,
  host: null,
  metrics: null,
  series: empty,
  processes: [],
  connections: [],
  findings: [],
  liveEvents: [],
  module: "command",
  focusPid: null,
  processQuery: "",
  toast: null,
  healthTab: null,

  setModule: (module) => set({ module }),
  focusProcess: (pid) => set(pid === null ? { focusPid: null } : { focusPid: pid, module: "process" }),
  searchProcesses: (processQuery) => set({ processQuery, module: "process" }),
  pushMetrics: (m) =>
    set((s) => ({
      metrics: m,
      series: {
        t: append(s.series.t, m.ts / 1000),
        cpu: append(s.series.cpu, m.cpu),
        mem: append(s.series.mem, (m.memUsed / Math.max(1, m.memTotal)) * 100),
        rx: append(s.series.rx, m.netRxRate),
        tx: append(s.series.tx, m.netTxRate),
      },
    })),
  pushEvent: (e) =>
    set((s) => (s.liveEvents.some((x) => x.id === e.id) ? s : { liveEvents: [e, ...s.liveEvents].slice(0, 300) })),
  notify: (text, tone = "ok") => {
    window.clearTimeout(toastTimer);
    set({ toast: { text, tone } });
    toastTimer = window.setTimeout(() => set({ toast: null }), 4200);
  },
}));
