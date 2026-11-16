//! Online reputation providers. Only a file hash is ever sent — never the file itself —
//! and only when the user explicitly asks. Keys live DPAPI-encrypted in `secrets`.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reputation {
    pub provider: String,
    pub found: bool,
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub label: Option<String>,
    pub link: String,
}

pub trait IntelProvider {
    fn name(&self) -> &'static str;
    fn lookup_sha256(&self, sha256: &str) -> Result<Reputation, String>;
}

pub struct VirusTotal {
    pub key: String,
}

impl IntelProvider for VirusTotal {
    fn name(&self) -> &'static str {
        "VirusTotal"
    }

    fn lookup_sha256(&self, sha256: &str) -> Result<Reputation, String> {
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Geçersiz SHA-256".into());
        }
        let link = format!("https://www.virustotal.com/gui/file/{sha256}");
        let resp = ureq::get(&format!("https://www.virustotal.com/api/v3/files/{sha256}"))
            .header("x-apikey", &self.key)
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| format!("VirusTotal'a ulaşılamadı: {e}"))?;
        let status = resp.status().as_u16();
        match status {
            404 => {
                return Ok(Reputation {
                    provider: self.name().into(),
                    found: false,
                    malicious: 0,
                    suspicious: 0,
                    harmless: 0,
                    undetected: 0,
                    label: None,
                    link,
                })
            }
            401 | 403 => return Err("VirusTotal API anahtarı geçersiz".into()),
            429 => return Err("VirusTotal kota sınırı aşıldı, biraz sonra tekrar deneyin".into()),
            200 => {}
            s => return Err(format!("VirusTotal beklenmeyen yanıt: HTTP {s}")),
        }
        let text = resp
            .into_body()
            .read_to_string()
            .map_err(|e| format!("Yanıt okunamadı: {e}"))?;
        let body: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("Yanıt çözümlenemedi: {e}"))?;
        let a = &body["data"]["attributes"];
        let st = &a["last_analysis_stats"];
        let n = |k: &str| st[k].as_u64().unwrap_or(0) as u32;
        Ok(Reputation {
            provider: self.name().into(),
            found: true,
            malicious: n("malicious"),
            suspicious: n("suspicious"),
            harmless: n("harmless"),
            undetected: n("undetected"),
            label: a["popular_threat_classification"]["suggested_threat_label"]
                .as_str()
                .map(str::to_string),
            link,
        })
    }
}
