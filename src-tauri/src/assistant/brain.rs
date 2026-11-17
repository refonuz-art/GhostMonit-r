//! Free conversation through the Claude API (optional; everything else works without it).
//!
//! The webview owns the conversation and the tool loop, because the tools act on the UI.
//! This side holds the key (DPAPI) and builds the request: the page can choose only the
//! system prompt, the messages and the tool list, never the endpoint, model or headers.
//! Raw HTTP is used because Rust has no official Anthropic SDK.

use std::time::Duration;

use serde_json::{json, Value};

use super::{secret, CLAUDE_KEY};
use crate::state::Shared;

const URL: &str = "https://api.anthropic.com/v1/messages";
const MODEL: &str = "claude-opus-5-5";

pub fn valid_key(k: &str) -> bool {
    k.starts_with("sk-ant-") && (30..=300).contains(&k.len()) && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn build_body(system: Value, messages: Value, tools: Value) -> Result<Value, String> {
    if !messages.is_array() || messages.as_array().is_some_and(|m| m.is_empty()) {
        return Err("Mesaj yok".into());
    }
    if !tools.is_array() {
        return Err("Araç listesi geçersiz".into());
    }
    Ok(json!({
        "model": MODEL,
        "max_tokens": 4000,
        "system": system,
        "messages": messages,
        "tools": tools,
        // A spoken assistant must answer quickly; short replies don't need deep thinking.
        "output_config": { "effort": "low" },
        "cache_control": { "type": "ephemeral" },
        // If a safety classifier declines, the API retries on a suitable model itself.
        "fallbacks": "default",
    }))
}

pub fn ask(shared: &Shared, system: Value, messages: Value, tools: Value) -> Result<Value, String> {
    let key = secret(shared, CLAUDE_KEY).ok_or("Claude API anahtarı ayarlanmamış (Ayarlar → Asistan)")?;
    let body = build_body(system, messages, tools)?;
    if body.to_string().len() > 2 * 1024 * 1024 {
        return Err("Konuşma çok uzadı; yeni bir konuşma başlatın".into());
    }
    let agent: ureq::Agent =
        ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(120))).build().into();
    let mut r = agent
        .post(URL)
        .header("x-api-key", &key)
        .header("anthropic-version", "2026-10-21")
        .header("anthropic-beta", "server-side-fallback-2026-07-01")
        .header("content-type", "application/json")
        .send(body.to_string())
        .map_err(|_| "Claude API'ye bağlanılamadı".to_string())?;
    let status = r.status().as_u16();
    let text = r.body_mut().with_config().limit(16 * 1024 * 1024).read_to_string().map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        let msg = v["error"]["message"].as_str().unwrap_or("");
        return Err(match status {
            401 => "Claude API anahtarı geçersiz".to_string(),
            429 => "Claude API kullanım sınırına ulaşıldı, biraz sonra tekrar deneyin".to_string(),
            529 | 503 => "Claude şu an yoğun, biraz sonra tekrar deneyin".to_string(),
            _ => format!("Claude API hata verdi (HTTP {status}) {msg}"),
        });
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_is_fixed_except_conversation() {
        let b = build_body(json!("sys"), json!([{"role":"user","content":"selam"}]), json!([])).unwrap();
        assert_eq!(b["model"], MODEL);
        assert_eq!(b["fallbacks"], "default");
        assert!(b.get("temperature").is_none());
        assert!(build_body(json!("s"), json!([]), json!([])).is_err());
        assert!(valid_key("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(!valid_key("sk-other-abcdefghijklmnopqrstuvwxyz0123456789"));
    }
}
