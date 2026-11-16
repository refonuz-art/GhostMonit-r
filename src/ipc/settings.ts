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
}

export interface UpdateInfo {
  current: string;
  version: string;
  notes: string | null;
  date: string | null;
}

export const settingsApi = {
  get: () => invoke<AppSettings>("get_settings"),
  save: (settings: AppSettings) => invoke<AppSettings>("save_settings", { settings }),
  quit: () => invoke<void>("quit_app"),
  checkUpdate: () => invoke<UpdateInfo | null>("check_update"),
  installUpdate: () => invoke<void>("install_update"),
};
