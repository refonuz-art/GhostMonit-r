//! Local known-bad hash database (SQLite table `bad_hashes`).
//! Import accepts any text/CSV file: every 64-char hex token is treated as a SHA-256
//! (MalwareBazaar exports, threat-feed dumps, hand-made lists all work).

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashDbStats {
    pub total: i64,
    pub sources: Vec<(String, i64)>,
}

pub fn import(conn: &Connection, path: &Path) -> Result<(u64, u64), String> {
    let source = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "içe aktarma".into());
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    let mut added = 0u64;
    let mut seen = 0u64;
    {
        let mut stmt = tx
            .prepare("INSERT OR IGNORE INTO bad_hashes (sha256, name, source) VALUES (?1, ?2, ?3)")
            .map_err(|e| e.to_string())?;
        for line in BufReader::new(f).lines() {
            let line = line.map_err(|e| e.to_string())?;
            if line.starts_with('#') {
                continue;
            }
            // Second quoted CSV field often carries a family/signature name; keep the line short.
            let label = line
                .split(',')
                .map(|s| s.trim().trim_matches('"'))
                .find(|s| !s.is_empty() && s.len() < 64 && s.chars().any(|c| c.is_ascii_alphabetic()) && !s.contains(' '))
                .map(str::to_string);
            for tok in line.split(|c: char| !c.is_ascii_hexdigit()) {
                if tok.len() == 64 {
                    seen += 1;
                    added += stmt
                        .execute(params![tok.to_ascii_lowercase(), label, source])
                        .map_err(|e| e.to_string())? as u64;
                }
            }
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok((added, seen))
}

pub const FEED_SOURCE: &str = "MalwareBazaar (otomatik)";
const FEED_URL: &str = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv";

/// Quote-aware CSV split: `"a, b", "c"` → ["a, b", "c"].
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for ch in line.chars() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur).trim().to_string()),
            c => cur.push(c),
        }
    }
    out.push(cur.trim().to_string());
    out
}

/// MalwareBazaar CSV export: header line `# "first_seen_utc","sha256_hash",…,"signature",…`.
/// The family name comes from the `signature` column, falling back to `file_type_guess`.
pub fn import_bazaar_csv(conn: &Connection, text: &str) -> Result<(u64, u64), String> {
    let mut cols: HashMap<String, usize> = HashMap::new();
    let split = csv_fields;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    let (mut added, mut seen) = (0u64, 0u64);
    {
        let mut stmt = tx
            .prepare("INSERT OR IGNORE INTO bad_hashes (sha256, name, source) VALUES (?1, ?2, ?3)")
            .map_err(|e| e.to_string())?;
        for line in text.lines() {
            let l = line.trim();
            if let Some(h) = l.strip_prefix('#') {
                if h.contains("sha256_hash") {
                    cols = split(h.trim()).into_iter().enumerate().map(|(i, c)| (c, i)).collect();
                }
                continue;
            }
            if l.is_empty() {
                continue;
            }
            let f = split(l);
            let get = |k: &str| cols.get(k).and_then(|&i| f.get(i)).map(String::as_str).filter(|v| !v.is_empty() && *v != "n/a");
            let Some(sha) = get("sha256_hash").filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit())) else {
                continue;
            };
            seen += 1;
            let name = get("signature").or_else(|| get("file_type_guess")).map(str::to_string);
            added += stmt.execute(params![sha.to_ascii_lowercase(), name, FEED_SOURCE]).map_err(|e| e.to_string())? as u64;
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    if seen == 0 {
        return Err("Yanıtta hash bulunamadı (biçim değişmiş olabilir)".into());
    }
    Ok((added, seen))
}

/// Download the last-48h export. Only the Auth-Key leaves the machine.
pub fn fetch_bazaar(key: &str) -> Result<String, String> {
    let url = FEED_URL.replace("{key}", key);
    let resp = ureq::get(&url)
        .header("User-Agent", "GhostMonitor/0.1")
        .config()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .build()
        .call()
        .map_err(|e| format!("Bağlantı kurulamadı: {e}"))?;
    let code = resp.status().as_u16();
    let body = resp.into_body().with_config().limit(64 * 1024 * 1024).read_to_string().map_err(|e| e.to_string())?;
    match code {
        200 => Ok(body),
        401 | 403 => Err("abuse.ch anahtarı geçersiz".into()),
        429 => Err("abuse.ch istek sınırı aşıldı; daha sonra tekrar denenecek".into()),
        c => Err(format!("abuse.ch HTTP {c}")),
    }
}

pub fn stats(conn: &Connection) -> rusqlite::Result<HashDbStats> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM bad_hashes", [], |r| r.get(0))?;
    let mut stmt = conn.prepare("SELECT source, COUNT(*) FROM bad_hashes GROUP BY source ORDER BY 2 DESC")?;
    let sources = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    Ok(HashDbStats { total, sources })
}

pub fn lookup(conn: &Connection, sha256: &str) -> Option<String> {
    conn.query_row(
        "SELECT COALESCE(name, source) FROM bad_hashes WHERE sha256 = ?1",
        [sha256.to_ascii_lowercase()],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .ok()
    .flatten()
}

pub fn clear(conn: &Connection) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM bad_hashes", [])
}

/// SHA-256 of running executables, computed lazily in the background.
#[derive(Clone)]
pub struct ExeHashes {
    map: Arc<Mutex<HashMap<String, (Option<SystemTime>, String)>>>,
    queued: Arc<Mutex<std::collections::HashSet<String>>>,
    tx: Sender<String>,
}

impl ExeHashes {
    pub fn new() -> Self {
        let (tx, rx) = channel::<String>();
        let map: Arc<Mutex<HashMap<String, (Option<SystemTime>, String)>>> = Default::default();
        let queued: Arc<Mutex<std::collections::HashSet<String>>> = Default::default();
        let (m2, q2) = (map.clone(), queued.clone());
        std::thread::Builder::new()
            .name("exe-hash".into())
            .spawn(move || {
                while let Ok(path) = rx.recv() {
                    let mt = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                    if let Ok(h) = super::file::sha256_file(Path::new(&path)) {
                        m2.lock().insert(path.clone(), (mt, h));
                    }
                    q2.lock().remove(&path);
                }
            })
            .expect("spawn exe-hash");
        Self { map, queued, tx }
    }

    pub fn get_or_queue(&self, path: &str) -> Option<String> {
        if let Some((_, h)) = self.map.lock().get(path) {
            return Some(h.clone());
        }
        if self.queued.lock().insert(path.to_string()) {
            let _ = self.tx.send(path.to_string());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    #[test]
    fn bazaar_csv_columns() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE bad_hashes (sha256 TEXT PRIMARY KEY, name TEXT, source TEXT)").unwrap();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let csv = format!(
            "################
# \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"file_type_guess\",\"signature\"
             \"2026-11-16 10:00:00\", \"{a}\", \"{m}\", \"exe\", \"AgentTesla\"
             \"2026-11-16 10:01:00\", \"{b}\", \"{m}\", \"dll\", \"n/a\"
",
            m = "c".repeat(32)
        );
        assert_eq!(import_bazaar_csv(&conn, &csv).unwrap(), (2, 2));
        assert_eq!(lookup(&conn, &a).as_deref(), Some("AgentTesla"));
        assert_eq!(lookup(&conn, &b).as_deref(), Some("dll"));
        assert_eq!(import_bazaar_csv(&conn, &csv).unwrap(), (0, 2), "idempotent");
        assert!(import_bazaar_csv(&conn, "<html>error</html>").is_err());
    }

    #[test]
    fn imports_hex_tokens_from_csv() {
        let s = Store::open_memory().unwrap();
        let p = std::env::temp_dir().join("gm_hashes.csv");
        std::fs::write(
            &p,
            "# header\n\"2024-01-01\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"AgentTesla\"\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\nnot-a-hash\n",
        )
        .unwrap();
        let (added, seen) = import(&s.conn, &p).unwrap();
        assert_eq!((added, seen), (2, 2));
        assert!(lookup(&s.conn, &"b".repeat(64)).is_some());
        assert_eq!(lookup(&s.conn, &"a".repeat(64)).as_deref(), Some("AgentTesla"));
        let (added2, _) = import(&s.conn, &p).unwrap();
        assert_eq!(added2, 0);
        let _ = std::fs::remove_file(p);
    }
}
