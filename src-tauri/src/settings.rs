//! User-adjustable behaviour. Stored as one JSON document in the `settings` table so new
//! fields get their defaults without a migration.

use serde::{Deserialize, Serialize};

use crate::model::Severity;
use crate::store::Store;

const KEY: &str = "app_settings";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "Ghost Monitor";
pub const HIDDEN_ARG: &str = "--hidden";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    /// Mirrors the HKCU Run value; the registry is the source of truth.
    pub autostart: bool,
    /// Closing the window keeps monitoring in the tray.
    pub close_to_tray: bool,
    pub notify: bool,
    pub notify_min_severity: Severity,
    pub startup_scan_minutes: u32,
    pub retention_days: u32,
    /// Watch Downloads/Desktop for new executables.
    pub file_watch: bool,
    /// Report drives being plugged in.
    pub usb_watch: bool,
    /// Pull the public malware hash feed daily (sends a request to abuse.ch).
    pub feed_auto_update: bool,
    /// Scheduled report: "off" | "daily" | "weekly".
    pub auto_report: String,
    pub auto_report_format: String,
    pub auto_report_dir: Option<String>,
    /// Check GitHub Releases for a new version (installing always needs a click).
    pub update_check: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            autostart: false,
            close_to_tray: true,
            notify: true,
            notify_min_severity: Severity::Medium,
            startup_scan_minutes: 10,
            retention_days: 30,
            file_watch: true,
            usb_watch: true,
            feed_auto_update: false,
            auto_report: "off".into(),
            auto_report_format: "pdf".into(),
            auto_report_dir: None,
            update_check: true,
        }
    }
}

impl AppSettings {
    pub fn load(st: &Store) -> Self {
        let mut s: Self = st
            .setting(KEY)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default();
        s.autostart = autostart_enabled();
        s.clamp();
        s
    }

    pub fn save(&self, st: &Store) -> Result<(), String> {
        st.set_setting(KEY, &serde_json::to_string(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }

    pub fn clamp(&mut self) {
        self.startup_scan_minutes = self.startup_scan_minutes.clamp(1, 24 * 60);
        self.retention_days = self.retention_days.clamp(1, 365);
        if !matches!(self.auto_report.as_str(), "off" | "daily" | "weekly") {
            self.auto_report = "off".into();
        }
        if !matches!(self.auto_report_format.as_str(), "pdf" | "json") {
            self.auto_report_format = "pdf".into();
        }
    }
}

fn run_key() -> std::io::Result<winreg::RegKey> {
    winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey_with_flags(RUN_KEY, winreg::enums::KEY_READ | winreg::enums::KEY_WRITE)
}

/// Enabled only if the Run value points at *this* executable.
pub fn autostart_enabled() -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    run_key()
        .and_then(|k| k.get_value::<String, _>(RUN_VALUE))
        .map(|v| v.to_ascii_lowercase().contains(&exe.to_string_lossy().to_ascii_lowercase()))
        .unwrap_or(false)
}

pub fn set_autostart(on: bool) -> Result<(), String> {
    let k = run_key().map_err(|e| e.to_string())?;
    if on {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        k.set_value(RUN_VALUE, &format!("\"{}\" {HIDDEN_ARG}", exe.display())).map_err(|e| e.to_string())
    } else {
        match k.delete_value(RUN_VALUE) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_take_defaults_and_values_are_clamped() {
        let st = Store::open_memory().unwrap();
        st.set_setting(KEY, r#"{"notify":false,"retentionDays":9999,"autoReport":"hourly"}"#).unwrap();
        let s = AppSettings::load(&st);
        assert!(!s.notify);
        assert!(s.close_to_tray, "default kept");
        assert_eq!(s.retention_days, 365);
        assert_eq!(s.auto_report, "off");
        assert_eq!(s.notify_min_severity, Severity::Medium);
    }
}
