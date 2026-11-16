//! Quarantine: move a suspicious file out of reach, encrypted so it can neither run nor be
//! opened by accident, and restore or delete it later.
//!
//! Each file is XORed with its own 32-byte random key stream (SHA-256 counter mode). The key
//! itself is DPAPI-protected in the database. This is containment, not secrecy: the point is
//! that the stored blob is inert and does not keep triggering antivirus scanners.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::now_ms;
use crate::state::Shared;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QItem {
    pub id: i64,
    pub original: String,
    pub sha256: String,
    pub size: i64,
    pub reason: String,
    pub created_at: i64,
}

const MAX_SIZE: u64 = 512 * 1024 * 1024;

fn dir(shared: &Shared) -> PathBuf {
    PathBuf::from(&shared.host.read().data_dir).join("quarantine")
}

fn random_key() -> Result<[u8; 32], String> {
    use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    let mut k = [0u8; 32];
    unsafe { BCryptGenRandom(None, &mut k, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }.ok().map_err(|e| e.message())?;
    Ok(k)
}

/// XOR `data` in place with SHA256(key || block_index) blocks starting at byte `offset`.
fn xor_stream(key: &[u8; 32], offset: u64, data: &mut [u8]) {
    let mut pos = offset;
    let mut i = 0;
    while i < data.len() {
        let block = pos / 32;
        let in_block = (pos % 32) as usize;
        let mut h = Sha256::new();
        h.update(key);
        h.update(block.to_le_bytes());
        let ks = h.finalize();
        let n = (32 - in_block).min(data.len() - i);
        for j in 0..n {
            data[i + j] ^= ks[in_block + j];
        }
        i += n;
        pos += n as u64;
    }
}

/// Stream-copy `src` → `dst` through the cipher. Returns the SHA-256 of the plaintext.
fn transform(src: &Path, dst: &Path, key: &[u8; 32], plaintext_is_src: bool) -> Result<String, String> {
    let mut r = std::fs::File::open(src).map_err(|e| format!("Dosya okunamadı: {e}"))?;
    let mut w = std::fs::OpenOptions::new().write(true).create_new(true).open(dst).map_err(|e| format!("Hedef yazılamadı: {e}"))?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut off = 0u64;
    let mut hasher = Sha256::new();
    loop {
        let n = r.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        let chunk = &mut buf[..n];
        if plaintext_is_src {
            hasher.update(&*chunk);
        }
        xor_stream(key, off, chunk);
        if !plaintext_is_src {
            hasher.update(&*chunk);
        }
        w.write_all(chunk).map_err(|e| e.to_string())?;
        off += n as u64;
    }
    w.sync_all().map_err(|e| e.to_string())?;
    Ok(hex::encode(hasher.finalize()))
}

pub fn list(shared: &Shared) -> Result<Vec<QItem>, String> {
    let st = shared.store.lock();
    let mut q = st
        .conn
        .prepare("SELECT id, original, sha256, size, reason, created_at FROM quarantine ORDER BY created_at DESC")
        .map_err(|e| e.to_string())?;
    let rows = q
        .query_map([], |r| Ok(QItem { id: r.get(0)?, original: r.get(1)?, sha256: r.get(2)?, size: r.get(3)?, reason: r.get(4)?, created_at: r.get(5)? }))
        .map_err(|e| e.to_string())?;
    Ok(rows.flatten().collect())
}

fn protected_path(p: &Path) -> bool {
    let l = p.to_string_lossy().to_ascii_lowercase();
    let win = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).to_ascii_lowercase();
    l.starts_with(&format!(r"{win}\system32")) || l.starts_with(&format!(r"{win}\syswow64")) || l.starts_with(&format!(r"{win}\winsxs"))
}

pub fn add(shared: &Shared, path: &str, reason: &str) -> Result<QItem, String> {
    let src = PathBuf::from(path);
    if !src.is_absolute() {
        return Err("Mutlak bir dosya yolu gerekli".into());
    }
    let meta = std::fs::symlink_metadata(&src).map_err(|_| "Dosya bulunamadı".to_string())?;
    if !meta.is_file() {
        return Err("Yalnızca normal dosyalar karantinaya alınabilir".into());
    }
    if meta.len() > MAX_SIZE {
        return Err("Dosya 512 MB'tan büyük; karantina için çok büyük".into());
    }
    if protected_path(&src) {
        return Err("Windows sistem klasöründeki dosyalar karantinaya alınamaz".into());
    }
    let own = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok());
    if own.is_some() && src.canonicalize().ok() == own {
        return Err("Ghost Monitor kendini karantinaya alamaz".into());
    }
    let d = dir(shared);
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    let key = random_key()?;
    let stored = d.join(format!("{}-{}.gmq", now_ms(), hex::encode(&key[..4])));
    let sha = match transform(&src, &stored, &key, true) {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&stored);
            return Err(e);
        }
    };
    // Original goes only after the encrypted copy is safely on disk.
    if let Err(e) = std::fs::remove_file(&src) {
        let _ = std::fs::remove_file(&stored);
        return Err(if e.raw_os_error() == Some(32) {
            "Dosya şu anda kullanılıyor (çalışan bir program olabilir). Önce işlemi sonlandırın.".into()
        } else {
            format!("Orijinal dosya silinemedi: {e}")
        });
    }
    let blob = crate::winapi::dpapi::protect(&key)?;
    let now = now_ms();
    let st = shared.store.lock();
    st.conn
        .execute(
            "INSERT INTO quarantine (original, stored, sha256, size, key, reason, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![path, stored.to_string_lossy(), sha, meta.len() as i64, blob, reason, now],
        )
        .map_err(|e| e.to_string())?;
    let id = st.conn.last_insert_rowid();
    Ok(QItem { id, original: path.into(), sha256: sha, size: meta.len() as i64, reason: reason.into(), created_at: now })
}

fn row(shared: &Shared, id: i64) -> Result<(String, PathBuf, String, Vec<u8>), String> {
    shared
        .store
        .lock()
        .conn
        .query_row("SELECT original, stored, sha256, key FROM quarantine WHERE id=?1", [id], |r| {
            Ok((r.get::<_, String>(0)?, PathBuf::from(r.get::<_, String>(1)?), r.get(2)?, r.get(3)?))
        })
        .map_err(|_| "Karantina kaydı bulunamadı".to_string())
}

/// Restore to the original location (or next to it with a suffix if a file now exists there).
pub fn restore(shared: &Shared, id: i64) -> Result<String, String> {
    let (original, stored, sha, blob) = row(shared, id)?;
    // The stored path must be inside our quarantine folder (defence against a tampered DB).
    if stored.parent() != Some(dir(shared).as_path()) {
        return Err("Karantina kaydı bozuk".into());
    }
    let key: [u8; 32] = crate::winapi::dpapi::unprotect(&blob)?.try_into().map_err(|_| "Anahtar bozuk".to_string())?;
    let mut target = PathBuf::from(&original);
    if target.exists() {
        let stem = target.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let ext = target.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
        target.set_file_name(format!("{stem} (geri yüklendi){ext}"));
    }
    if let Some(p) = target.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let got = match transform(&stored, &target, &key, false) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_file(&target);
            return Err(e);
        }
    };
    if got != sha {
        let _ = std::fs::remove_file(&target);
        return Err("Geri yüklenen dosya doğrulanamadı (karantina kopyası bozulmuş)".into());
    }
    let _ = std::fs::remove_file(&stored);
    let _ = shared.store.lock().conn.execute("DELETE FROM quarantine WHERE id=?1", [id]);
    Ok(target.to_string_lossy().into_owned())
}

pub fn delete(shared: &Shared, id: i64) -> Result<(), String> {
    let (_, stored, _, _) = row(shared, id)?;
    if stored.parent() == Some(dir(shared).as_path()) {
        let _ = std::fs::remove_file(&stored);
    }
    shared.store.lock().conn.execute("DELETE FROM quarantine WHERE id=?1", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_roundtrip_any_offset() {
        let key = [7u8; 32];
        let plain: Vec<u8> = (0..1000u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut whole = plain.clone();
        xor_stream(&key, 0, &mut whole);
        assert_ne!(whole, plain);
        // Encrypting in uneven chunks must equal encrypting at once.
        let mut chunked = plain.clone();
        let (a, b) = chunked.split_at_mut(77);
        xor_stream(&key, 0, a);
        xor_stream(&key, 77, b);
        assert_eq!(chunked, whole);
        xor_stream(&key, 0, &mut whole);
        assert_eq!(whole, plain);
    }

    #[test]
    fn file_roundtrip() {
        let d = std::env::temp_dir().join(format!("gmq-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (a, b, c) = (d.join("a.exe"), d.join("a.gmq"), d.join("a2.exe"));
        std::fs::write(&a, b"MZ fake executable payload").unwrap();
        let key = random_key().unwrap();
        let h1 = transform(&a, &b, &key, true).unwrap();
        assert!(!std::fs::read(&b).unwrap().starts_with(b"MZ"));
        let h2 = transform(&b, &c, &key, false).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(std::fs::read(&c).unwrap(), b"MZ fake executable payload");
        let _ = std::fs::remove_dir_all(&d);
    }
}
