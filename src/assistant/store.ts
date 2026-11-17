import { create } from "zustand";
import type { Severity } from "../ipc/types";

export type Mode = "idle" | "listening" | "thinking" | "speaking";

export interface Line {
  id: number;
  who: "user" | "ayla" | "alert";
  text: string;
  severity?: Severity;
  at: number;
}

export interface Pending {
  question: string;
  run: () => Promise<string>;
}

interface AylaState {
  /** Assistant switched on in Settings (set by the Assistant component). */
  enabled: boolean;
  open: boolean;
  mode: Mode;
  lines: Line[];
  pending: Pending | null;
  /** Severity of the alert being presented; tints the hologram until it fades. */
  alert: Severity | null;
  /** Alerts are still shown but not spoken. */
  muted: boolean;
  subtitle: string | null;
  /** Push-to-talk, provided by the Assistant component so other screens can start listening. */
  talk: () => void;
  setOpen: (v: boolean) => void;
  setMode: (m: Mode) => void;
  add: (who: Line["who"], text: string, severity?: Severity) => void;
  setPending: (p: Pending | null) => void;
  setAlert: (s: Severity | null) => void;
  setMuted: (v: boolean) => void;
  setSubtitle: (s: string | null) => void;
}

let seq = 0;

export const useAyla = create<AylaState>((set) => ({
  enabled: false,
  open: false,
  mode: "idle",
  lines: [],
  pending: null,
  alert: null,
  muted: false,
  subtitle: null,
  talk: () => {},
  setOpen: (open) => set({ open }),
  setMode: (mode) => set({ mode }),
  add: (who, text, severity) =>
    set((s) => ({ lines: [...s.lines, { id: ++seq, who, text, severity, at: Date.now() }].slice(-80) })),
  setPending: (pending) => set({ pending }),
  setAlert: (alert) => set({ alert }),
  setMuted: (muted) => set({ muted }),
  setSubtitle: (subtitle) => set({ subtitle }),
}));
