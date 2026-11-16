import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { ConnHistoryRow, EventQuery, Finding, GeoStatus, KillResult, SecurityEvent, Snapshot } from "./types";

export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export const api = {
  snapshot: () => invoke<Snapshot>("get_snapshot"),
  events: (q: EventQuery) => invoke<SecurityEvent[]>("get_events", { q }),
  findingHistory: (limit?: number) => invoke<Finding[]>("get_finding_history", { limit }),
  killProcess: (pid: number, confirmed: boolean) => invoke<KillResult>("kill_process", { pid, confirmed }),
  setTrust: (key: string, trusted: boolean) => invoke<void>("set_trust", { key, trusted }),
  setFindingStatus: (key: string, status: "open" | "dismissed" | "investigating") =>
    invoke<void>("set_finding_status", { key, status }),
  setBackground: (background: boolean) => invoke<void>("set_background", { background }),
  relaunchAdmin: () => invoke<void>("relaunch_admin"),
  reveal: (path: string) => invoke<void>("reveal_in_explorer", { path }),
  geoStatus: () => invoke<GeoStatus>("geo_status"),
  downloadGeo: () => invoke<GeoStatus>("download_geo"),
  connHistory: (search?: string, limit?: number) => invoke<ConnHistoryRow[]>("conn_history", { search, limit }),
};

export function on<T>(channel: string, cb: (payload: T) => void): Promise<UnlistenFn> {
  return listen<T>(`gm://${channel}`, (e) => cb(e.payload));
}
