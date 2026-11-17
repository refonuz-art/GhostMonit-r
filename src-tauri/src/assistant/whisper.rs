//! Offline Turkish speech recognition with whisper.cpp (no account, nothing leaves the PC).
//!
//! The official whisper.cpp Windows build and model are downloaded once into
//! `<data_dir>\whisper`, each pinned to a SHA-256, and run as a hidden child process.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};

use crate::state::Shared;

const BIN_URL: &str = "https://github.com/ggml-org/whisper.cpp/releases/download/b5454/whisper-bin-x64.zip";
const BIN_SHA: &str = "6ba69e3482d7826214f90a6a9c84ca07782aec1e1d0c6a7c30c994fd5d816ccb";
pub const MODEL_FILE: &str = "ggml-large-v3-turbo-q5_0.bin";
const MODEL_URL: &str = "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-large-v3-turbo-q5_0.bin";
const MODEL_SHA: &str = "394221709cd5ad1f40c46e6031ca61bce88931e6e088c188294c6d5a55ffa7e2";
const MODEL_SIZE: u64 = 574_041_195;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallProgress {
    pub stage: String,
    pub done: u64,
    pub total: u64,
}

pub fn dir(shared: &Shared) -> PathBuf {
    PathBuf::from(&shared.host.read().data_dir).join("whisper")
}

pub fn installed(shared: &Shared) -> bool {
    let d = dir(shared);
    d.join("whisper-cli.exe").is_file() && d.join(MODEL_FILE).metadata().is_ok_and(|m| m.len() == MODEL_SIZE)
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).timeout_connect(Some(Duration::from_secs(20))).build().into()
}

/// Stream `url` into `dest`, verifying its SHA-256; a mismatch leaves nothing behind.
fn download(url: &str, sha: &str, dest: &Path, mut progress: impl FnMut(u64, u64)) -> Result<(), String> {
    let mut r = agent().get(url).header("User-Agent", "GhostMonitor").call().map_err(|e| format!("İndirme başlatılamadı: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("İndirme başarısız (HTTP {})", r.status().as_u16()));
    }
    let total = r.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).unwrap_or(0);
    let part = dest.with_extension("part");
    let mut f = std::fs::File::create(&part).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut body = r.body_mut().with_config().limit(2 * 1024 * 1024 * 1024).reader();
    let mut buf = vec![0u8; 256 * 1024];
    let mut done = 0u64;
    let mut last = 0u64;
    loop {
        let n = body.read(&mut buf).map_err(|e| format!("İndirme kesildi: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        done += n as u64;
        if done - last > 2 * 1024 * 1024 {
            last = done;
            progress(done, total);
        }
    }
    drop(f);
    if hex::encode(hasher.finalize()) != sha {
        let _ = std::fs::remove_file(&part);
        return Err("İndirilen dosyanın doğrulaması tutmadı; kurulmadı".into());
    }
    std::fs::rename(&part, dest).map_err(|e| e.to_string())
}

fn file_sha(p: &Path) -> Option<String> {
    let mut f = std::fs::File::open(p).ok()?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).ok()?;
    Some(hex::encode(h.finalize()))
}

pub fn install(app: &AppHandle, shared: &Shared) -> Result<(), String> {
    let d = dir(shared);
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    let emit = |stage: &str, done: u64, total: u64| {
        let _ = app.emit("gm://assistant-install", InstallProgress { stage: stage.into(), done, total });
    };

    if !d.join("whisper-cli.exe").is_file() {
        let zip = d.join("whisper-bin-x64.zip");
        if file_sha(&zip).as_deref() != Some(BIN_SHA) {
            emit("program", 0, 0);
            download(BIN_URL, BIN_SHA, &zip, |a, b| emit("program", a, b))?;
        }
        let tmp = d.join("extract");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
        let tar = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join(r"System32\tar.exe");
        let (code, _) = crate::guard::run_hidden(
            &tar.to_string_lossy(),
            &["-xf", &zip.to_string_lossy(), "-C", &tmp.to_string_lossy()],
            Duration::from_secs(120),
        )?;
        if code != 0 {
            return Err("Program arşivi açılamadı".into());
        }
        let rel = tmp.join("Release");
        for e in std::fs::read_dir(&rel).map_err(|e| e.to_string())?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let keep = name == "whisper-cli.exe" || (name.ends_with(".dll") && (name.starts_with("ggml") || name == "whisper.dll"));
            if keep {
                std::fs::copy(e.path(), d.join(&name)).map_err(|e| e.to_string())?;
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_file(&zip);
    }

    if !installed(shared) {
        emit("model", 0, MODEL_SIZE);
        download(MODEL_URL, MODEL_SHA, &d.join(MODEL_FILE), |a, b| emit("model", a, b.max(MODEL_SIZE)))?;
    }
    emit("done", 1, 1);
    Ok(())
}

pub fn transcribe(shared: &Shared, wav: &[u8]) -> Result<String, String> {
    if wav.len() < 44 || &wav[0..4] != b"RIFF" || &wav[8..12] != b"WAVE" {
        return Err("Ses kaydı geçersiz".into());
    }
    if !installed(shared) {
        return Err("Yerel konuşma tanıma kurulu değil (Ayarlar → Asistan)".into());
    }
    let d = dir(shared);
    let input = d.join(format!("rec-{}.wav", std::process::id()));
    std::fs::write(&input, wav).map_err(|e| e.to_string())?;
    let threads = std::thread::available_parallelism().map(|n| n.get().clamp(2, 8)).unwrap_or(4).to_string();
    let exe = d.join("whisper-cli.exe");
    let model = d.join(MODEL_FILE);
    let res = run(
        &exe,
        &["-m", &model.to_string_lossy(), "-f", &input.to_string_lossy(), "-l", "tr", "-nt", "-np", "-t", &threads, "-bs", "1", "-bo", "1"],
        Duration::from_secs(60),
    );
    let _ = std::fs::remove_file(&input);
    Ok(clean(&res?))
}

/// Run hidden; stdout is drained on a thread and the (chatty) log on stderr is discarded,
/// so a full pipe can never stall the child.
fn run(exe: &Path, args: &[&str], timeout: Duration) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let mut child = std::process::Command::new(exe)
        .args(args)
        .creation_flags(0x0800_0000)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Konuşma tanıma başlatılamadı: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("çıktı yok")?;
    let reader = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = stdout.read_to_end(&mut v);
        v
    });
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(st) => break st,
            None if started.elapsed() > timeout => {
                let _ = child.kill();
                return Err("Konuşma tanıma zaman aşımına uğradı".into());
            }
            None => std::thread::sleep(Duration::from_millis(30)),
        }
    };
    let out = reader.join().unwrap_or_default();
    if !status.success() {
        return Err("Konuşma tanınamadı".into());
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

/// whisper marks silence and noise with bracketed tags; those are not words.
pub fn clean(out: &str) -> String {
    let joined = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ");
    let mut s = String::new();
    let mut depth = 0;
    for c in joined.chars() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => s.push(c),
            _ => {}
        }
    }
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    // Typical hallucinations on near-silence.
    let low = s.replace('İ', "i").to_lowercase();
    if ["altyazı", "abone ol", "izlediğiniz için teşekkür"].iter().any(|h| low.contains(h)) && s.len() < 60 {
        return String::new();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_tags_and_hallucinations() {
        assert_eq!(clean(" [BLANK_AUDIO]\n Opera'yı aç.\n"), "Opera'yı aç.");
        assert_eq!(clean("(müzik) merhaba"), "merhaba");
        assert_eq!(clean("İzlediğiniz için teşekkürler."), "");
    }
}
