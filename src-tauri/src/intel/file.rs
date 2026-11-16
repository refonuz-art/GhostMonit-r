//! Local file analysis. Works fully offline; online providers are separate and opt-in.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::engine::{rules::sig, score};
use crate::model::{Severity, Signal, SignatureInfo, SignatureState};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Motw {
    pub zone: u32,
    pub zone_name: String,
    pub host_url: Option<String>,
    pub referrer_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileReport {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub kind: String,
    pub detail: Option<String>,
    pub extension: String,
    pub signature: SignatureInfo,
    pub motw: Option<Motw>,
    pub known_bad: Option<String>,
    pub signals: Vec<Signal>,
    pub score: u32,
    pub severity: Severity,
}

pub const EXEC_EXT: &[&str] = &[
    "exe", "scr", "pif", "com", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1",
    "psm1", "lnk", "msi", "msp", "jar", "cpl", "dll", "reg", "sys", "appx", "msix", "iso", "img",
];
const DOC_EXT: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif",
    "bmp", "mp3", "mp4", "avi", "mkv", "zip", "rar", "csv",
];

fn ms(t: std::io::Result<std::time::SystemTime>) -> Option<i64> {
    t.ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

pub struct Hashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

pub fn hash_file(path: &Path) -> std::io::Result<Hashes> {
    let mut r = BufReader::with_capacity(1 << 20, File::open(path)?);
    let (mut a, mut b, mut c) = (Sha256::new(), Sha1::new(), Md5::new());
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        a.update(&buf[..n]);
        b.update(&buf[..n]);
        c.update(&buf[..n]);
    }
    Ok(Hashes { sha256: hex::encode(a.finalize()), sha1: hex::encode(b.finalize()), md5: hex::encode(c.finalize()) })
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut r = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Identify by content, not by extension.
pub fn sniff(head: &[u8]) -> (String, Option<String>) {
    let starts = |m: &[u8]| head.len() >= m.len() && &head[..m.len()] == m;
    if starts(b"MZ") {
        return ("Çalıştırılabilir (PE)".into(), pe_detail(head));
    }
    let k = if starts(b"%PDF") {
        "PDF belgesi"
    } else if starts(b"PK\x03\x04") {
        "ZIP arşivi (Office/JAR/APK olabilir)"
    } else if starts(&[0xD0, 0xCF, 0x11, 0xE0]) {
        "OLE bileşik belge (eski Office/MSI)"
    } else if starts(b"\x89PNG") {
        "PNG görüntü"
    } else if starts(&[0xFF, 0xD8, 0xFF]) {
        "JPEG görüntü"
    } else if starts(b"GIF8") {
        "GIF görüntü"
    } else if starts(b"Rar!") {
        "RAR arşivi"
    } else if starts(&[0x37, 0x7A, 0xBC, 0xAF]) {
        "7-Zip arşivi"
    } else if starts(&[0x1F, 0x8B]) {
        "GZIP arşivi"
    } else if starts(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        "Windows kısayolu (LNK)"
    } else if starts(b"CD001") || (head.len() > 0x8006 && &head[0x8001..0x8006] == b"CD001") {
        "ISO disk görüntüsü"
    } else if starts(b"#!") {
        "Betik (shebang)"
    } else if head.iter().take(4096).all(|b| *b == b'\t' || *b == b'\n' || *b == b'\r' || (*b >= 0x20 && *b != 0x7F) || *b >= 0x80) {
        "Metin"
    } else {
        "Bilinmeyen ikili veri"
    };
    (k.into(), None)
}

fn pe_detail(h: &[u8]) -> Option<String> {
    let rd16 = |o: usize| h.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let rd32 = |o: usize| h.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let pe = rd32(0x3C)? as usize;
    if h.get(pe..pe + 4)? != b"PE\0\0" {
        return Some("MZ başlığı var, PE imzası yok".into());
    }
    let machine = match rd16(pe + 4)? {
        0x14c => "x86",
        0x8664 => "x64",
        0xAA64 => "ARM64",
        0x1c4 => "ARM",
        _ => "bilinmeyen mimari",
    };
    let stamp = rd32(pe + 8)?;
    let chars = rd16(pe + 22)?;
    let opt = pe + 24;
    let magic = match rd16(opt)? {
        0x10b => "PE32",
        0x20b => "PE32+",
        _ => "PE",
    };
    let subsystem = match rd16(opt + 68)? {
        1 => "sürücü/yerel",
        2 => "GUI",
        3 => "konsol",
        _ => "diğer",
    };
    let dll = chars & 0x2000 != 0;
    // Deterministic builds (most Microsoft binaries) store a hash here, not a date.
    let built = match chrono::DateTime::from_timestamp(stamp as i64, 0) {
        Some(d) if d <= chrono::Utc::now() && d.timestamp() > 631_152_000 => {
            format!("derleme damgası {}", d.format("%Y-%m-%d"))
        }
        _ => "deterministik derleme (damga tarih değil)".to_string(),
    };
    Some(format!(
        "{magic} {machine}, {}{subsystem}, {built}",
        if dll { "DLL, " } else { "" }
    ))
}

pub fn read_motw(path: &str) -> Option<Motw> {
    let s = std::fs::read_to_string(format!("{path}:Zone.Identifier")).ok()?;
    let mut zone = None;
    let (mut host, mut refr) = (None, None);
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("ZoneId=") {
            zone = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("HostUrl=") {
            host = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("ReferrerUrl=") {
            refr = Some(v.trim().to_string());
        }
    }
    let zone = zone?;
    let zone_name = match zone {
        0 => "Bu bilgisayar",
        1 => "Yerel intranet",
        2 => "Güvenilen siteler",
        3 => "İnternet",
        4 => "Kısıtlı siteler",
        _ => "Bilinmeyen bölge",
    }
    .to_string();
    Some(Motw { zone, zone_name, host_url: host, referrer_url: refr })
}

pub fn analyze(
    path: &str,
    signature: impl FnOnce(&str) -> SignatureInfo,
    known_bad: impl FnOnce(&str) -> Option<String>,
) -> Result<FileReport, String> {
    let p = Path::new(path);
    let meta = std::fs::metadata(p).map_err(|e| format!("Dosya okunamadı: {e}"))?;
    if meta.is_dir() {
        return Err("Bu bir klasör; lütfen bir dosya seçin".into());
    }
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let extension = p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();

    let mut head = vec![0u8; 0x8010];
    let n = File::open(p).and_then(|mut f| f.read(&mut head)).map_err(|e| e.to_string())?;
    head.truncate(n);
    let (kind, detail) = sniff(&head);
    let is_pe = kind.starts_with("Çalıştırılabilir");

    let hashes = hash_file(p).map_err(|e| format!("Hash hesaplanamadı: {e}"))?;
    let sig_info = if is_pe || ["msi", "ps1", "cat", "sys", "cab", "appx", "msix"].contains(&extension.as_str()) {
        signature(path)
    } else {
        SignatureInfo { state: SignatureState::Unsigned, publisher: None }
    };
    let motw = read_motw(path);
    let bad = known_bad(&hashes.sha256);

    // ---- signals ----
    let mut s: Vec<Signal> = Vec::new();
    if let Some(b) = &bad {
        s.push(sig("hash.known_bad", "Bilinen zararlı dosya (hash eşleşmesi)", 100, b.clone()));
    }
    if name.contains('\u{202E}') {
        s.push(sig("file.rtlo", "Dosya adında yön değiştirme karakteri (RTLO) var", 50, name.clone()));
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() >= 3 {
        let inner = parts[parts.len() - 2].to_ascii_lowercase();
        if DOC_EXT.contains(&inner.as_str()) && EXEC_EXT.contains(&extension.as_str()) {
            s.push(sig("file.double_ext", "Çift uzantı ile belge gibi görünen çalıştırılabilir", 35, name.clone()));
        }
    }
    if is_pe && DOC_EXT.contains(&extension.as_str()) {
        s.push(sig("file.ext_mismatch", "Uzantı içerikle uyuşmuyor: çalıştırılabilir dosya gizlenmiş", 45, format!(".{extension} ama içerik PE")));
    }
    let executable = is_pe || EXEC_EXT.contains(&extension.as_str());
    let unsigned = matches!(sig_info.state, SignatureState::Unsigned | SignatureState::Invalid);
    if executable && sig_info.state == SignatureState::Invalid {
        s.push(sig("sig.invalid", "Geçersiz dijital imza", 35, sig_info.publisher.clone().unwrap_or_default()));
    } else if is_pe && unsigned {
        s.push(sig("sig.unsigned", "Dijital imza yok", 10, path.to_string()));
    }
    if executable {
        if let Some(m) = &motw {
            if m.zone >= 3 && unsigned {
                s.push(sig(
                    "file.motw",
                    "İnternetten indirilmiş imzasız çalıştırılabilir",
                    20,
                    m.host_url.clone().unwrap_or_else(|| m.zone_name.clone()),
                ));
            }
        }
        let lp = path.to_ascii_lowercase();
        if unsigned && (lp.contains("\\appdata\\local\\temp\\") || lp.contains("\\windows\\temp\\")) {
            s.push(sig("loc.temp", "Geçici klasörde imzasız çalıştırılabilir", 20, path.to_string()));
        }
    }
    if ["vbs", "vbe", "js", "jse", "wsf", "hta"].contains(&extension.as_str()) {
        s.push(sig("file.script", "Windows Script Host betiği (sık kötüye kullanılır)", 10, name.clone()));
    }

    let (total, severity) = score(&s);
    Ok(FileReport {
        path: path.to_string(),
        name,
        size: meta.len(),
        created: ms(meta.created()),
        modified: ms(meta.modified()),
        accessed: ms(meta.accessed()),
        sha256: hashes.sha256,
        sha1: hashes.sha1,
        md5: hashes.md5,
        kind,
        detail,
        extension,
        signature: sig_info,
        motw,
        known_bad: bad,
        signals: s,
        score: total,
        severity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_pe_and_pdf() {
        let notepad = std::fs::read(r"C:\Windows\System32\notepad.exe").unwrap();
        let (k, d) = sniff(&notepad[..4096]);
        assert!(k.contains("PE"));
        assert!(d.unwrap().contains("x64"));
        assert_eq!(sniff(b"%PDF-1.7 ...").0, "PDF belgesi");
    }

    #[test]
    fn disguised_executable_is_flagged() {
        let dir = std::env::temp_dir().join("gm_file_test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("fatura.pdf.exe");
        let mut bytes = std::fs::read(r"C:\Windows\System32\notepad.exe").unwrap();
        bytes.truncate(8192); // break the signature on purpose
        std::fs::write(&p, &bytes).unwrap();
        let r = analyze(
            &p.to_string_lossy(),
            |_| SignatureInfo { state: SignatureState::Unsigned, publisher: None },
            |_| None,
        )
        .unwrap();
        assert!(r.signals.iter().any(|s| s.rule == "file.double_ext"));
        assert_eq!(r.sha256.len(), 64);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn known_hash_is_critical() {
        let p = std::env::temp_dir().join("gm_hash_test.txt");
        std::fs::write(&p, b"hello").unwrap();
        let r = analyze(
            &p.to_string_lossy(),
            |_| SignatureInfo { state: SignatureState::Unsigned, publisher: None },
            |h| (h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824").then(|| "test".into()),
        )
        .unwrap();
        assert_eq!(r.severity, Severity::Critical);
        let _ = std::fs::remove_file(p);
    }
}
