//! Azure Speech: Turkish neural voice (text → mp3) and Turkish recognition (wav → text).
//! The key and region are DPAPI-encrypted in the secrets table and never reach the webview.

use std::time::Duration;

use serde_json::Value;

use super::{secret, AZURE_KEY, AZURE_REGION};
use crate::state::Shared;

pub fn valid_region(r: &str) -> bool {
    (3..=30).contains(&r.len()) && r.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub fn valid_key(k: &str) -> bool {
    (20..=128).contains(&k.len()) && k.chars().all(|c| c.is_ascii_alphanumeric())
}

fn creds(shared: &Shared) -> Result<(String, String), String> {
    match (secret(shared, AZURE_KEY), secret(shared, AZURE_REGION)) {
        (Some(k), Some(r)) if valid_region(&r) => Ok((k, r)),
        _ => Err("Azure Speech anahtarı ayarlanmamış (Ayarlar → Asistan)".into()),
    }
}

fn agent(secs: u64) -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(secs))).build().into()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

fn status_error(code: u16) -> String {
    match code {
        401 | 403 => "Azure Speech anahtarı veya bölgesi hatalı".into(),
        429 => "Azure Speech kullanım sınırına ulaşıldı, biraz sonra tekrar deneyin".into(),
        c => format!("Azure Speech hata verdi (HTTP {c})"),
    }
}

/// mp3 audio for `text`. `rate` is a multiplier (1.0 = normal).
pub fn synthesize(shared: &Shared, text: &str, voice: &str, rate: f32) -> Result<Vec<u8>, String> {
    if !crate::settings::AZURE_VOICES.contains(&voice) {
        return Err("Bilinmeyen ses".into());
    }
    let text: String = text.chars().filter(|c| !c.is_control() || *c == '\n').take(1500).collect();
    if text.trim().is_empty() {
        return Err("Boş metin".into());
    }
    let (key, region) = creds(shared)?;
    let pct = ((rate.clamp(0.7, 1.4) - 1.0) * 100.0).round() as i32;
    let ssml = format!(
        "<speak version='1.0' xml:lang='tr-TR'><voice name='{voice}'><prosody rate='{pct:+}%'>{}</prosody></voice></speak>",
        xml_escape(&text)
    );
    let url = format!("https://{region}.tts.speech.microsoft.com/cognitiveservices/v1");
    let mut r = agent(20)
        .post(&url)
        .header("Ocp-Apim-Subscription-Key", &key)
        .header("Content-Type", "application/ssml+xml")
        .header("X-Microsoft-OutputFormat", "audio-24khz-48kbitrate-mono-mp3")
        .header("User-Agent", "GhostMonitor")
        .send(ssml)
        .map_err(|_| "Azure Speech'e bağlanılamadı".to_string())?;
    if !r.status().is_success() {
        return Err(status_error(r.status().as_u16()));
    }
    r.body_mut().with_config().limit(8 * 1024 * 1024).read_to_vec().map_err(|e| e.to_string())
}

/// Turkish text from a 16 kHz mono 16-bit WAV recording.
pub fn recognize(shared: &Shared, wav: &[u8]) -> Result<String, String> {
    if wav.len() < 44 || &wav[0..4] != b"RIFF" || &wav[8..12] != b"WAVE" {
        return Err("Ses kaydı geçersiz".into());
    }
    if wav.len() > 3 * 1024 * 1024 {
        return Err("Ses kaydı çok uzun".into());
    }
    let (key, region) = creds(shared)?;
    let url = format!(
        "https://{region}.stt.speech.microsoft.com/speech/recognition/conversation/cognitiveservices/v1?language=tr-TR&format=simple"
    );
    let mut r = agent(25)
        .post(&url)
        .header("Ocp-Apim-Subscription-Key", &key)
        .header("Content-Type", "audio/wav; codecs=audio/pcm; samplerate=16000")
        .header("Accept", "application/json")
        .send(wav)
        .map_err(|_| "Azure Speech'e bağlanılamadı".to_string())?;
    if !r.status().is_success() {
        return Err(status_error(r.status().as_u16()));
    }
    let body = r.body_mut().read_to_string().map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    match v["RecognitionStatus"].as_str() {
        Some("Success") => Ok(v["DisplayText"].as_str().unwrap_or("").to_string()),
        Some("NoMatch") | Some("InitialSilenceTimeout") | Some("BabbleTimeout") => Ok(String::new()),
        Some(other) => Err(format!("Konuşma tanınamadı ({other})")),
        None => Err("Konuşma tanınamadı".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_and_escaping() {
        assert!(valid_region("westeurope") && valid_region("eastus2"));
        assert!(!valid_region("west europe") && !valid_region("evil.com/x") && !valid_region("ab"));
        assert!(valid_key("0123456789abcdef0123456789ABCDEF"));
        assert!(!valid_key("short") && !valid_key("0123456789abcdef0123456789ABCDE/"));
        assert_eq!(xml_escape("a<b>&'\""), "a&lt;b&gt;&amp;&apos;&quot;");
    }
}
