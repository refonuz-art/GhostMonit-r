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
    /// Decoy files + mass rename/rewrite detection in the user's document folders.
    pub ransom_shield: bool,
    /// Read Windows event logs (Security needs administrator rights).
    pub eventlog_watch: bool,
    /// Read the ARP table for new devices on the home network.
    pub lan_watch: bool,
    /// Phone notifications via Telegram / Discord.
    pub remote_notify: bool,
    pub remote_min_severity: Severity,
    /// Include event details (paths, addresses) in phone notifications.
    pub remote_details: bool,
    /// Voice assistant: speaks alerts and answers commands.
    pub assistant_enabled: bool,
    pub assistant_name: String,
    /// "windows" (installed voice, offline) | "azure" (Azure Speech neural voice, needs a key).
    pub assistant_voice: String,
    pub assistant_azure_voice: String,
    /// Speech rate, 0.7 .. 1.4.
    pub assistant_rate: f32,
    pub assistant_speak_alerts: bool,
    pub assistant_min_severity: Severity,
    /// Show the hologram in the corner of every screen.
    pub assistant_float: bool,
    /// City for weather answers (sent to Open-Meteo only when weather is asked).
    pub assistant_city: Option<String>,
}

pub const AZURE_VOICES: [&str; 2] = ["tr-TR-EmelNeural", "tr-TR-AhmetNeural"];

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
            ransom_shield: true,
            eventlog_watch: true,
            lan_watch: true,
            remote_notify: false,
            remote_min_severity: Severity::High,
            remote_details: false,
            assistant_enabled: true,
            assistant_name: "Ayla".into(),
            assistant_voice: "windows".into(),
            assistant_azure_voice: AZURE_VOICES[0].into(),
            assistant_rate: 1.0,
            assistant_speak_alerts: true,
            assistant_min_severity: Severity::High,
            assistant_float: true,
            assistant_city: None,
        }
    }
}

impl AppSettings {
    pub fn load(st: &Store) -> Self {
        let mut s = st.setting(KEY).ok().flatten().map(|v| Self::parse_lenient(&v)).unwrap_or_default();
        s.autostart = autostart_enabled();
        s.clamp();
        s
    }

    /// Keeps every saved value that still parses. One field a newer or older version no
    /// longer understands falls back to its default instead of resetting all settings.
    fn parse_lenient(raw: &str) -> Self {
        use serde_json::Value;
        if let Ok(s) = serde_json::from_str(raw) {
            return s;
        }
        let Ok(Value::Object(saved)) = serde_json::from_str::<Value>(raw) else { return Self::default() };
        let Ok(Value::Object(mut merged)) = serde_json::to_value(Self::default()) else { return Self::default() };
        for (k, v) in saved {
            let prev = merged.insert(k.clone(), v);
            if serde_json::from_value::<Self>(Value::Object(merged.clone())).is_err() {
                match prev {
                    Some(p) => merged.insert(k, p),
                    None => merged.remove(&k),
                };
            }
        }
        serde_json::from_value(Value::Object(merged)).unwrap_or_default()
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
        if !matches!(self.assistant_voice.as_str(), "windows" | "azure") {
            self.assistant_voice = "windows".into();
        }
        if !AZURE_VOICES.contains(&self.assistant_azure_voice.as_str()) {
            self.assistant_azure_voice = AZURE_VOICES[0].into();
        }
        self.assistant_rate = if self.assistant_rate.is_finite() { self.assistant_rate.clamp(0.7, 1.4) } else { 1.0 };
        let name: String = self.assistant_name.trim().chars().filter(|c| c.is_alphanumeric() || *c == ' ').take(20).collect();
        self.assistant_name = if name.is_empty() { "Ayla".into() } else { name };
        self.assistant_city = self
            .assistant_city
            .take()
            .map(|c| c.trim().chars().take(60).collect::<String>())
            .filter(|c| !c.is_empty());
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
    fn one_bad_field_does_not_reset_the_rest() {
        let st = Store::open_memory().unwrap();
        st.set_setting(KEY, r#"{"remoteNotify":true,"assistantName":"Lilith","remoteMinSeverity":"APOCALYPSE","notify":"maybe"}"#)
            .unwrap();
        let s = AppSettings::load(&st);
        assert!(s.remote_notify, "valid value kept");
        assert_eq!(s.assistant_name, "Lilith");
        assert_eq!(s.remote_min_severity, AppSettings::default().remote_min_severity, "bad enum falls back");
        assert_eq!(s.notify, AppSettings::default().notify, "bad type falls back");
    }

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
