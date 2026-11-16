import { useEffect } from "react";
import { api, isTauri, on } from "../ipc/api";
import type { ConnectionInfo, Finding, ProcessInfo, SecurityEvent, SystemMetrics } from "../ipc/types";
import { useGhost } from "../state/store";

/** Wires backend push events into the store. Mounted once at the root. */
export function useBridge() {
  useEffect(() => {
    if (!isTauri) return;
    const unsubs: Promise<() => void>[] = [];
    const set = useGhost.setState;

    api
      .snapshot()
      .then((s) => {
        set({
          host: s.host,
          processes: s.processes,
          connections: s.connections,
          findings: s.findings,
          ready: true,
        });
        if (s.metrics) useGhost.getState().pushMetrics(s.metrics);
      })
      .catch(() => set({ ready: true }));

    api
      .events({ limit: 80 })
      .then((evs) =>
        set((st) => {
          const seen = new Set(st.liveEvents.map((e) => e.id));
          const merged = [...st.liveEvents, ...evs.filter((e) => !seen.has(e.id))];
          merged.sort((a, b) => b.ts - a.ts || b.id - a.id);
          return { liveEvents: merged.slice(0, 300) };
        }),
      )
      .catch(() => {});

    unsubs.push(on<SystemMetrics>("metrics", (m) => useGhost.getState().pushMetrics(m)));
    unsubs.push(on<ProcessInfo[]>("processes", (processes) => set({ processes })));
    unsubs.push(on<ConnectionInfo[]>("connections", (connections) => set({ connections })));
    unsubs.push(on<Finding[]>("findings", (findings) => set({ findings })));
    unsubs.push(on<SecurityEvent>("event", (e) => useGhost.getState().pushEvent(e)));

    const vis = () => api.setBackground(document.hidden).catch(() => {});
    document.addEventListener("visibilitychange", vis);

    return () => {
      document.removeEventListener("visibilitychange", vis);
      unsubs.forEach((p) => p.then((u) => u()));
    };
  }, []);
}
