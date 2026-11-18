import { invoke } from "@tauri-apps/api/core";
import type { Severity } from "./types";

export interface AppSettings {
  autostart: boolean;
  closeToTray: boolean;
  notify: boolean;
  notifyMinSeverity: Severity;
  startupScanMinutes: number;
  retentionDays: number;
  fileWatch: boolean;
  usbWatch: boolean;
  feedAutoUpdate: boolean;
  autoReport: "off" | "daily" | "weekly";
  autoReportFormat: "pdf" | "json";
  autoReportDir: string | null;
  updateCheck: boolean;
  ransomShield: boolean;
  eventlogWatch: boolean;
  lanWatch: boolean;
  remoteNotify: boolean;
  remoteMinSeverity: Severity;
  remoteDetails: boolean;
  assistantEnabled: boolean;
  assistantName: string;
  assistantVoice: "windows" | "azure";
  assistantAzureVoice: "tr-TR-EmelNeural" | "tr-TR-AhmetNeural";
  assistantRate: number;
  assistantSpeakAlerts: boolean;
  assistantMinSeverity: Severity;
  assistantFloat: boolean;
  assistantCity: string | null;
  assistantMorning: boolean;
  assistantWake: boolean;
  usbShield: boolean;
  dnsAlerts: boolean;
  remoteActions: boolean;
  remoteWeekly: boolean;
}

export interface UpdateInfo {
  current: string;
  version: string;
  notes: string | null;
  date: string | null;
}

export const settingsApi = {
  get: () => invoke<AppSettings>("get_settings"),
  save: (settings: AppSettings) =>
    invoke<AppSettings>("save_settings", { settings }).then((saved) => {
      window.dispatchEvent(new CustomEvent<AppSettings>("gm-settings", { detail: saved }));
      return saved;
    }),
  quit: () => invoke<void>("quit_app"),
  checkUpdate: () => invoke<UpdateInfo | null>("check_update"),
  installUpdate: () => invoke<void>("install_update"),
};
