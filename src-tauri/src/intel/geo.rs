//! Offline country/ASN lookup using DB-IP Lite databases (CC BY 4.0, https://db-ip.com).
//! The databases are not bundled; the user downloads them from Settings / Network Watch.

use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::{geoip2, Reader};
use parking_lot::RwLock;
use serde::Serialize;

pub const COUNTRY_FILE: &str = "dbip-country-lite.mmdb";
pub const ASN_FILE: &str = "dbip-asn-lite.mmdb";

pub struct Geo {
    dir: PathBuf,
    country: RwLock<Option<Reader<Vec<u8>>>>,
    asn: RwLock<Option<Reader<Vec<u8>>>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoStatus {
    pub country_db: bool,
    pub asn_db: bool,
    pub built: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoHit {
    pub country: Option<String>,
    pub asn: Option<String>,
}

impl Geo {
    pub fn new(data_dir: &Path) -> Self {
        let dir = data_dir.join("geo");
        let g = Self { dir, country: RwLock::new(None), asn: RwLock::new(None) };
        g.reload();
        g
    }

    pub fn reload(&self) {
        *self.country.write() = Reader::open_readfile(self.dir.join(COUNTRY_FILE)).ok();
        *self.asn.write() = Reader::open_readfile(self.dir.join(ASN_FILE)).ok();
    }

    pub fn status(&self) -> GeoStatus {
        let built = self.country.read().as_ref().map(|r| {
            chrono::DateTime::from_timestamp(r.metadata().build_epoch as i64, 0)
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default()
        });
        GeoStatus { country_db: self.country.read().is_some(), asn_db: self.asn.read().is_some(), built }
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoHit {
        let mut hit = GeoHit::default();
        if let Some(r) = self.country.read().as_ref() {
            if let Ok(Some(c)) = r.lookup(ip).and_then(|l| l.decode::<geoip2::Country>()) {
                hit.country = c.country.iso_code.map(str::to_string);
            }
        }
        if let Some(r) = self.asn.read().as_ref() {
            if let Ok(Some(a)) = r.lookup(ip).and_then(|l| l.decode::<geoip2::Asn>()) {
                hit.asn = match (a.autonomous_system_number, a.autonomous_system_organization) {
                    (Some(n), Some(o)) => Some(format!("AS{n} {o}")),
                    (Some(n), None) => Some(format!("AS{n}")),
                    (None, Some(o)) => Some(o.to_string()),
                    _ => None,
                };
            }
        }
        hit
    }

    /// Download the current (or previous) month's DB-IP Lite databases.
    pub fn download(&self) -> Result<GeoStatus, String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let now = chrono::Utc::now();
        let prev = now - chrono::Duration::days(28);
        let months = [now.format("%Y-%m").to_string(), prev.format("%Y-%m").to_string()];
        for (kind, file) in [("country", COUNTRY_FILE), ("asn", ASN_FILE)] {
            let mut last_err = String::new();
            let mut ok = false;
            for m in &months {
                let url = format!("https://download.db-ip.com/free/dbip-{kind}-lite-{m}.mmdb.gz");
                match fetch_gz(&url) {
                    Ok(bytes) => {
                        // Validate before replacing the old file.
                        Reader::from_source(bytes.clone()).map_err(|e| e.to_string())?;
                        let tmp = self.dir.join(format!("{file}.part"));
                        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
                        // Readers hold the old file in memory, so replacing is safe.
                        std::fs::rename(&tmp, self.dir.join(file)).map_err(|e| e.to_string())?;
                        ok = true;
                        break;
                    }
                    Err(e) => last_err = e,
                }
            }
            if !ok {
                return Err(format!("{kind} veritabanı indirilemedi: {last_err}"));
            }
        }
        self.reload();
        Ok(self.status())
    }
}

fn fetch_gz(url: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .header("User-Agent", "GhostMonitor/0.1")
        .call()
        .map_err(|e| e.to_string())?;
    let reader = resp.into_body().into_reader().take(256 * 1024 * 1024);
    let mut gz = flate2::read::GzDecoder::new(reader);
    let mut out = Vec::new();
    gz.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}
