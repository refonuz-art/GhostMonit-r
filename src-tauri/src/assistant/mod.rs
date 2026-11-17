//! Voice assistant backend: program launching, weather, Azure speech and the optional
//! Claude conversation. Voice, the hologram and the command parser live in the frontend
//! (`src/assistant`).

pub mod apps;
pub mod brain;
pub mod speech;
pub mod weather;

use serde::Serialize;

use crate::state::Shared;

pub const AZURE_KEY: &str = "azure_speech_key";
pub const AZURE_REGION: &str = "azure_speech_region";
pub const CLAUDE_KEY: &str = "anthropic_key";

pub(crate) fn secret(shared: &Shared, name: &str) -> Option<String> {
    crate::commands_intel::secret(shared, name)
}

pub(crate) fn put_secret(shared: &Shared, name: &str, value: Option<&str>) -> Result<(), String> {
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantStatus {
    pub azure: bool,
    /// The region is not secret; shown so the user can see what is configured.
    pub azure_region: Option<String>,
    pub claude: bool,
}

pub fn status(shared: &Shared) -> AssistantStatus {
    let region = secret(shared, AZURE_REGION);
    AssistantStatus { azure: secret(shared, AZURE_KEY).is_some() && region.is_some(), azure_region: region, claude: secret(shared, CLAUDE_KEY).is_some() }
}

pub fn set_azure(shared: &Shared, key: Option<String>, region: Option<String>) -> Result<(), String> {
    let key = key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty());
    let region = region.map(|r| r.trim().to_ascii_lowercase().replace(' ', "")).filter(|r| !r.is_empty());
    match (key, region) {
        (Some(k), Some(r)) => {
            if !speech::valid_key(&k) {
                return Err("Azure Speech anahtarı biçimi geçersiz".into());
            }
            if !speech::valid_region(&r) {
                return Err("Bölge geçersiz (ör. westeurope)".into());
            }
            put_secret(shared, AZURE_KEY, Some(&k))?;
            put_secret(shared, AZURE_REGION, Some(&r))
        }
        (None, None) => {
            put_secret(shared, AZURE_KEY, None)?;
            put_secret(shared, AZURE_REGION, None)
        }
        _ => Err("Anahtar ve bölge birlikte girilmeli".into()),
    }
}

pub fn set_claude(shared: &Shared, key: Option<String>) -> Result<(), String> {
    match key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty()) {
        Some(k) if brain::valid_key(&k) => put_secret(shared, CLAUDE_KEY, Some(&k)),
        Some(_) => Err("Claude API anahtarı biçimi geçersiz (sk-ant- ile başlamalı)".into()),
        None => put_secret(shared, CLAUDE_KEY, None),
    }
}
