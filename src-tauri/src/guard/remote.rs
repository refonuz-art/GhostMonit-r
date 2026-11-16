//! Phone notifications through a Telegram bot or a Discord webhook.
//!
//! Credentials are DPAPI-encrypted in the secrets table. Only the event title, severity and
//! computer name are sent unless the user opts in to details (paths and addresses can be
//! personal). Sends are rate limited and happen on a background thread.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use serde::Serialize;

use super::now_ms;
use crate::model::{SecurityEvent, Severity};
use crate::state::Shared;

const TG_TOKEN: &str = "telegram_token";
const TG_CHAT: &str = "telegram_chat";
const DISCORD: &str = "discord_webhook";
const MIN_GAP_MS: i64 = 60_000;
static LAST_SENT: AtomicI64 = AtomicI64::new(0);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteStatus {
    pub telegram: bool,
    pub discord: bool,
}

fn get(shared: &Shared, name: &str) -> Option<String> {
    crate::commands_intel::secret(shared, name)
}

fn put(shared: &Shared, name: &str, value: Option<&str>) -> Result<(), String> {
    let st = shared.store.lock();
    match value {
        Some(v) => {
            let blob = crate::winapi::dpapi::protect(v.as_bytes())?;
            st.conn
                .execute("INSERT OR REPLACE INTO secrets (name, blob) VALUES (?1, ?2)", rusqlite::params![name, blob])
                .map_err(|e| e.to_string())?;
        }
        None => {
            st.conn.execute("DELETE FROM secrets WHERE name=?1", [name]).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub fn status(shared: &Shared) -> RemoteStatus {
    RemoteStatus { telegram: get(shared, TG_TOKEN).is_some() && get(shared, TG_CHAT).is_some(), discord: get(shared, DISCORD).is_some() }
}

pub fn valid_tg_token(t: &str) -> bool {
    let Some((id, rest)) = t.split_once(':') else { return false };
    !id.is_empty() && id.len() <= 15 && id.chars().all(|c| c.is_ascii_digit())
        && rest.len() >= 30 && rest.len() <= 64 && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn valid_tg_chat(c: &str) -> bool {
    let digits = c.strip_prefix('-').unwrap_or(c);
    (!digits.is_empty() && digits.len() <= 20 && digits.chars().all(|ch| ch.is_ascii_digit()))
        || (c.starts_with('@') && c.len() > 5 && c.len() <= 33 && c[1..].chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_'))
}

/// Only genuine Discord webhook URLs, so the setting can't be turned into a request to an
/// arbitrary (e.g. internal) address.
pub fn valid_discord(u: &str) -> bool {
    let rest = u.strip_prefix("https://discord.com/api/webhooks/").or_else(|| u.strip_prefix("https://discordapp.com/api/webhooks/")).or_else(|| u.strip_prefix("https://ptb.discord.com/api/webhooks/"));
    let Some(rest) = rest else { return false };
    let mut parts = rest.split('/');
    let (Some(id), Some(tok), None) = (parts.next(), parts.next(), parts.next()) else { return false };
    id.chars().all(|c| c.is_ascii_digit()) && !id.is_empty() && tok.len() >= 30 && tok.len() <= 100
        && tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn set_telegram(shared: &Shared, token: Option<String>, chat: Option<String>) -> Result<(), String> {
    let token = token.map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    let chat = chat.map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    match (token, chat) {
        (Some(t), Some(c)) => {
            if !valid_tg_token(&t) {
                return Err("Telegram bot anahtarı biçimi geçersiz (123456:ABC… şeklinde olmalı)".into());
            }
            if !valid_tg_chat(&c) {
                return Err("Sohbet kimliği geçersiz (sayı veya @kanaladi olmalı)".into());
            }
            put(shared, TG_TOKEN, Some(&t))?;
            put(shared, TG_CHAT, Some(&c))
        }
        (None, None) => {
            put(shared, TG_TOKEN, None)?;
            put(shared, TG_CHAT, None)
        }
        _ => Err("Bot anahtarı ve sohbet kimliği birlikte girilmeli".into()),
    }
}

pub fn set_discord(shared: &Shared, url: Option<String>) -> Result<(), String> {
    match url.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()) {
        Some(u) if valid_discord(&u) => put(shared, DISCORD, Some(&u)),
        Some(_) => Err("Discord webhook adresi geçersiz (https://discord.com/api/webhooks/… olmalı)".into()),
        None => put(shared, DISCORD, None),
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(15))).build().into()
}

fn send_text(shared: &Shared, text: &str) -> Result<usize, String> {
    let mut sent = 0;
    let mut errors = Vec::new();
    if let (Some(t), Some(c)) = (get(shared, TG_TOKEN), get(shared, TG_CHAT)) {
        let url = format!("https://api.telegram.org/bot{t}/sendMessage");
        let body = serde_json::json!({ "chat_id": c, "text": text, "disable_web_page_preview": true });
        match agent().post(&url).header("Content-Type", "application/json").send(body.to_string()) {
            Ok(r) if r.status().is_success() => sent += 1,
            Ok(r) => errors.push(format!("Telegram: HTTP {}", r.status().as_u16())),
            // Never echo the URL: it contains the bot token.
            Err(_) => errors.push("Telegram: bağlantı kurulamadı".into()),
        }
    }
    if let Some(u) = get(shared, DISCORD) {
        let body = serde_json::json!({ "content": text, "allowed_mentions": { "parse": [] } });
        match agent().post(&u).header("Content-Type", "application/json").send(body.to_string()) {
            Ok(r) if r.status().is_success() => sent += 1,
            Ok(r) => errors.push(format!("Discord: HTTP {}", r.status().as_u16())),
            Err(_) => errors.push("Discord: bağlantı kurulamadı".into()),
        }
    }
    if sent == 0 && !errors.is_empty() {
        return Err(errors.join(" · "));
    }
    if sent == 0 {
        return Err("Telefon bildirimi için Telegram veya Discord ayarlanmamış".into());
    }
    Ok(sent)
}

pub fn test(shared: &Shared) -> Result<usize, String> {
    let host = shared.host.read().hostname.clone();
    send_text(shared, &format!("👻 Ghost Monitor ({host}): test bildirimi. Bu kanal çalışıyor."))
}

fn sev_tr(s: Severity) -> &'static str {
    crate::shell::severity_tr(s)
}

/// Called for every emitted event; sends in the background when it qualifies.
pub fn maybe_send(app: &tauri::AppHandle, shared: &Shared, e: &SecurityEvent) {
    use tauri::Manager;
    let s = shared.settings.read().clone();
    if !s.remote_notify || e.severity < s.remote_min_severity.max(Severity::Medium) {
        return;
    }
    let now = now_ms();
    let last = LAST_SENT.load(Ordering::Relaxed);
    if now - last < MIN_GAP_MS || LAST_SENT.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err() {
        return;
    }
    let host = shared.host.read().hostname.clone();
    let mut text = format!("👻 Ghost Monitor ({host})\n[{}] {}", sev_tr(e.severity), e.title);
    if s.remote_details && !e.detail.is_empty() {
        let d: String = e.detail.chars().take(600).collect();
        text.push_str(&format!("\n{d}"));
    }
    let Some(shared) = app.try_state::<std::sync::Arc<Shared>>().map(|s| s.inner().clone()) else { return };
    std::thread::spawn(move || {
        if let Err(err) = send_text(&shared, &text) {
            log::warn!("remote notify: {err}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_validation() {
        assert!(valid_tg_token("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1"));
        assert!(!valid_tg_token("123456789:short"));
        assert!(!valid_tg_token("abc:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1"));
        assert!(!valid_tg_token("1:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1/../x"));
        assert!(valid_tg_chat("-1001234567890") && valid_tg_chat("12345") && valid_tg_chat("@benim_kanal"));
        assert!(!valid_tg_chat("12a") && !valid_tg_chat("@a"));
        assert!(valid_discord("https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJ-1234567890"));
        assert!(!valid_discord("https://discord.com.evil.net/api/webhooks/1/abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(!valid_discord("http://discord.com/api/webhooks/1/abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(!valid_discord("https://discord.com/api/webhooks/1/abcdefghijklmnopqrstuvwxyz0123456789/extra"));
        assert!(!valid_discord("https://discord.com/api/webhooks/1/abcdefghijklmnopqrst?x=@everyone"));
    }
}
