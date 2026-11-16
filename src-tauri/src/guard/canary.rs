//! Ransomware shield.
//!
//! 1. Decoy ("canary") files at both alphabetical ends of Documents, Desktop and Pictures.
//!    Nothing legitimate opens them; any change, rename or deletion is a near-certain sign
//!    of mass encryption.
//! 2. ReadDirectoryChangesW over the user's document folders: a burst of document files
//!    being renamed to an unknown extension, or many documents rewritten within seconds.
//!
//! On alert the processes writing the most to disk right now are listed as suspects, so
//! the user can suspend or terminate them. Nothing is terminated automatically.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tauri::AppHandle;

use super::{emit, finding, now_ms, set_findings};
use crate::engine::rules::sig;
use crate::model::Severity;
use crate::monitor::{emit_event, event};
use crate::state::Shared;
use crate::watchers::known_folder;

const NAMES: [&str; 2] = ["!!GhostMonitor-tuzak-dosya.docx", "zz GhostMonitor-tuzak-dosya.xlsx"];
const WINDOW: Duration = Duration::from_secs(20);
const RENAME_BURST: usize = 20;
const WRITE_BURST: usize = 40;

/// Document and media types users care about (and ransomware targets).
pub const DOC_EXT: &[&str] = &[
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "ods", "odp", "csv", "jpg",
    "jpeg", "png", "gif", "bmp", "tif", "tiff", "heic", "webp", "psd", "raw", "cr2", "nef", "mp3", "wav",
    "flac", "mp4", "mov", "avi", "mkv", "zip", "rar", "7z", "sql", "db", "pst", "md", "json", "xml",
];

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanaryStatus {
    pub enabled: bool,
    pub files: Vec<String>,
    pub watched_folders: Vec<String>,
    pub tripped: Option<i64>,
    pub last_alert: Option<String>,
}

struct Canary {
    path: PathBuf,
    sha: String,
}

fn content(name: &str) -> Vec<u8> {
    let mut s = format!(
        "Ghost Monitor fidye yazılımı tuzak dosyası ({name}).\r\n\
         Bu dosyayı açmayın, taşımayın veya silmeyin. Bir program bu dosyayı değiştirirse\r\n\
         Ghost Monitor bunu fidye yazılımı belirtisi olarak raporlar.\r\n\
         Kalkanı Ayarlar → Fidye yazılımı kalkanı bölümünden kapatabilirsiniz.\r\n"
    );
    while s.len() < 4096 {
        s.push_str("--------------------------------------------------------------\r\n");
    }
    s.into_bytes()
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn set_hidden(p: &Path, hidden: bool) {
    use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL};
    let w = crate::winapi::wide(&p.to_string_lossy());
    unsafe {
        let _ = SetFileAttributesW(
            windows::core::PCWSTR(w.as_ptr()),
            if hidden { FILE_ATTRIBUTE_HIDDEN } else { FILE_ATTRIBUTE_NORMAL },
        );
    }
}

fn folders() -> Vec<PathBuf> {
    use windows::Win32::UI::Shell::{FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Pictures};
    [FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Pictures].iter().filter_map(known_folder).filter(|p| p.is_dir()).collect()
}

fn watch_roots() -> Vec<PathBuf> {
    use windows::Win32::UI::Shell::{FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Videos};
    let mut v: Vec<PathBuf> = [FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Pictures, FOLDERID_Videos, FOLDERID_Music]
        .iter()
        .filter_map(known_folder)
        .filter(|p| p.is_dir())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn plant() -> Vec<Canary> {
    let mut out = Vec::new();
    for dir in folders() {
        for name in NAMES {
            let path = dir.join(name);
            let body = content(name);
            let want = sha(&body);
            let ok = std::fs::read(&path).map(|b| sha(&b) == want).unwrap_or(false);
            if !ok {
                set_hidden(&path, false);
                if std::fs::write(&path, &body).is_err() {
                    continue;
                }
            }
            set_hidden(&path, true);
            out.push(Canary { path, sha: want });
        }
    }
    out
}

pub fn remove_all() {
    for dir in folders() {
        for name in NAMES {
            let p = dir.join(name);
            set_hidden(&p, false);
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Top disk writers over ~1 s, excluding ourselves and the System process.
pub fn top_writers(n: usize) -> Vec<(u32, String, u64)> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let Ok(mut sys) = System::new() else { return vec![] };
    let kind = ProcessRefreshKind::nothing().with_disk_usage();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    std::thread::sleep(Duration::from_millis(1000));
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    let me = std::process::id();
    let mut v: Vec<(u32, String, u64)> = sys
        .processes()
        .values()
        .map(|p| (p.pid().as_u32(), p.name().to_string_lossy().into_owned(), p.disk_usage().written_bytes))
        .filter(|(pid, _, w)| *pid > 4 && *pid != me && *w > 0)
        .collect();
    v.sort_by(|a, b| b.2.cmp(&a.2));
    v.truncate(n);
    v
}

fn ext_of(p: &str) -> String {
    Path::new(p).extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

/// Sliding-window burst counter fed by the directory watchers.
#[derive(Default)]
pub struct Burst {
    renames: VecDeque<(Instant, String)>,
    writes: VecDeque<(Instant, String)>,
}

impl Burst {
    /// `old`→`new` rename where a document gets an extension that isn't a document type.
    pub fn rename(&mut self, now: Instant, old: &str, new: &str) {
        let (a, b) = (ext_of(old), ext_of(new));
        if DOC_EXT.contains(&a.as_str()) && a != b && !DOC_EXT.contains(&b.as_str()) {
            self.renames.push_back((now, new.to_string()));
        }
    }
    pub fn write(&mut self, now: Instant, path: &str) {
        if DOC_EXT.contains(&ext_of(path).as_str()) {
            self.writes.push_back((now, path.to_string()));
        }
    }
    fn trim(&mut self, now: Instant) {
        while self.renames.front().is_some_and(|(t, _)| now.duration_since(*t) > WINDOW) {
            self.renames.pop_front();
        }
        while self.writes.front().is_some_and(|(t, _)| now.duration_since(*t) > WINDOW) {
            self.writes.pop_front();
        }
    }
    /// (distinct renamed docs, distinct rewritten docs) inside the window.
    pub fn counts(&mut self, now: Instant) -> (usize, usize, Vec<String>) {
        self.trim(now);
        let r: HashSet<&String> = self.renames.iter().map(|(_, p)| p).collect();
        let w: HashSet<&String> = self.writes.iter().map(|(_, p)| p).collect();
        let sample = self.renames.iter().chain(self.writes.iter()).rev().take(5).map(|(_, p)| p.clone()).collect();
        (r.len(), w.len(), sample)
    }
    pub fn clear(&mut self) {
        self.renames.clear();
        self.writes.clear();
    }
}

/// True when the file was created more than two minutes ago: copying or importing new
/// files is normal, rewriting many existing documents at once is what encryption looks like.
fn existed_before(path: &str) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.created())
        .ok()
        .and_then(|c| c.elapsed().ok())
        .is_some_and(|age| age > Duration::from_secs(120))
}

/// Paths that rewrite many documents legitimately (build output, sync caches, VCS).
fn noisy(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    ["\\node_modules\\", "\\.git\\", "\\target\\", "\\appdata\\", "\\$recycle.bin\\", "\\.vs\\", "\\dist\\", "\\build\\"]
        .iter()
        .any(|n| l.contains(n))
}

fn watch_dir(root: PathBuf, burst: Arc<parking_lot::Mutex<Burst>>, shared: Arc<Shared>) {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadDirectoryChangesW, FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_NEW_NAME, FILE_ACTION_RENAMED_OLD_NAME,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
        FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let w = crate::winapi::wide(&root.to_string_lossy());
    let Ok(h) = (unsafe {
        CreateFileW(
            windows::core::PCWSTR(w.as_ptr()),
            FILE_LIST_DIRECTORY.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }) else {
        log::warn!("canary: cannot watch {}", root.display());
        return;
    };
    let mut buf = vec![0u64; 8192]; // 64 KiB, 8-byte aligned (DWORD alignment required)
    let mut pending_old: Option<String> = None;
    loop {
        let mut got = 0u32;
        let ok = unsafe {
            ReadDirectoryChangesW(
                h,
                buf.as_mut_ptr() as *mut _,
                (buf.len() * 8) as u32,
                true,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                Some(&mut got),
                None,
                None,
            )
        };
        if ok.is_err() {
            std::thread::sleep(Duration::from_secs(30));
            continue;
        }
        if !shared.settings.read().ransom_shield {
            continue;
        }
        let now = Instant::now();
        let base = buf.as_ptr() as *const u8;
        let mut off = 0usize;
        let mut b = burst.lock();
        while got > 0 && off + std::mem::size_of::<FILE_NOTIFY_INFORMATION>() <= got as usize {
            // SAFETY: the kernel filled `got` bytes with FILE_NOTIFY_INFORMATION records,
            // each DWORD aligned; we never read past `got`.
            let info = unsafe { &*(base.add(off) as *const FILE_NOTIFY_INFORMATION) };
            let len = info.FileNameLength as usize / 2;
            let name_end = off + std::mem::offset_of!(FILE_NOTIFY_INFORMATION, FileName) + len * 2;
            if name_end > got as usize {
                break;
            }
            let name = unsafe { std::slice::from_raw_parts(info.FileName.as_ptr(), len) };
            let rel = String::from_utf16_lossy(name);
            let full = format!("{}\\{rel}", root.display());
            if !noisy(&full) {
                match info.Action {
                    a if a == FILE_ACTION_RENAMED_OLD_NAME => pending_old = Some(full),
                    a if a == FILE_ACTION_RENAMED_NEW_NAME => {
                        if let Some(old) = pending_old.take() {
                            b.rename(now, &old, &full);
                        }
                    }
                    a if a == FILE_ACTION_MODIFIED && existed_before(&full) => b.write(now, &full),
                    _ => {}
                }
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            off += info.NextEntryOffset as usize;
        }
    }
}

pub fn spawn(app: AppHandle, shared: Arc<Shared>) {
    let burst = Arc::new(parking_lot::Mutex::new(Burst::default()));
    let roots = watch_roots();
    shared.guard.write().canary.watched_folders = roots.iter().map(|p| p.display().to_string()).collect();
    for root in roots {
        let (b, s) = (burst.clone(), shared.clone());
        let _ = std::thread::Builder::new().name("ransom-watch".into()).spawn(move || watch_dir(root, b, s));
    }
    std::thread::Builder::new()
        .name("canary".into())
        .spawn(move || run(app, shared, burst))
        .expect("spawn canary");
}

fn run(app: AppHandle, shared: Arc<Shared>, burst: Arc<parking_lot::Mutex<Burst>>) {
    std::thread::sleep(Duration::from_secs(5));
    let mut canaries: Vec<Canary> = Vec::new();
    let mut enabled = false;
    let mut cooldown: Option<Instant> = None;
    let mut stat: HashMap<PathBuf, (u64, Option<std::time::SystemTime>)> = HashMap::new();
    loop {
        let want = shared.settings.read().ransom_shield;
        if want != enabled {
            enabled = want;
            if enabled {
                canaries = plant();
                stat.clear();
            } else {
                remove_all();
                canaries.clear();
                burst.lock().clear();
                set_findings(&shared, "ransom:", vec![]);
            }
            let mut g = shared.guard.write();
            g.canary.enabled = enabled;
            g.canary.files = canaries.iter().map(|c| c.path.display().to_string()).collect();
            drop(g);
            emit(&app, &shared);
        }
        if !enabled {
            std::thread::sleep(Duration::from_secs(3));
            continue;
        }
        if cooldown.is_some_and(|t| t.elapsed() < Duration::from_secs(300)) {
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        if cooldown.take().is_some() {
            canaries = plant(); // re-arm after an alert
            stat.clear();
        }

        // ---- decoys ----
        let mut touched = Vec::new();
        for c in &canaries {
            let meta = std::fs::metadata(&c.path).ok();
            let cur = meta.as_ref().map(|m| (m.len(), m.modified().ok()));
            match (cur, stat.get(&c.path)) {
                (None, _) => touched.push(format!("{} silindi veya taşındı", c.path.display())),
                (Some(now), Some(prev)) if now == *prev => {}
                (Some(now), _) => {
                    let same = std::fs::read(&c.path).map(|b| sha(&b) == c.sha).unwrap_or(true);
                    if !same {
                        touched.push(format!("{} değiştirildi", c.path.display()));
                    }
                    stat.insert(c.path.clone(), now);
                }
            }
        }

        // ---- bursts ----
        let (renamed, rewritten, sample) = burst.lock().counts(Instant::now());
        let mut signals = Vec::new();
        if !touched.is_empty() {
            signals.push(sig("ransom.canary", "Fidye yazılımı tuzak dosyasına dokunuldu", 100, touched.join("; ")));
        }
        if renamed >= RENAME_BURST {
            signals.push(sig(
                "ransom.rename_burst",
                "Çok sayıda belge bilinmeyen uzantıyla yeniden adlandırıldı",
                70,
                format!("{renamed} dosya / 20 sn — ör. {}", sample.first().cloned().unwrap_or_default()),
            ));
        }
        if rewritten >= WRITE_BURST {
            signals.push(sig(
                "ransom.write_burst",
                "Çok sayıda belge saniyeler içinde yeniden yazıldı",
                40,
                format!("{rewritten} dosya / 20 sn — ör. {}", sample.first().cloned().unwrap_or_default()),
            ));
        }
        if !signals.is_empty() {
            alert(&app, &shared, signals);
            burst.lock().clear();
            cooldown = Some(Instant::now());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn alert(app: &AppHandle, shared: &Shared, mut signals: Vec<crate::model::Signal>) {
    let writers = top_writers(3);
    let pids: Vec<u32> = writers.iter().map(|w| w.0).collect();
    if !writers.is_empty() {
        let list = writers.iter().map(|(pid, n, b)| format!("{n} (PID {pid}, {} KB/sn)", b / 1024)).collect::<Vec<_>>().join(", ");
        signals.push(sig("ransom.suspects", "Şu anda diske en çok yazan işlemler", 0, list));
    }
    let key = format!("ransom:{}", now_ms());
    let detail = signals.iter().filter(|s| s.weight > 0).map(|s| s.label.clone()).collect::<Vec<_>>().join(" · ");
    if let Some(mut f) = finding(&key, "ransomware", "Belgeler / Masaüstü / Resimler", "Fidye yazılımı davranışı".into(), signals, pids.clone()) {
        // Decoys and mass renames are never a footnote; a write burst alone keeps its own score.
        let strong = f.signals.iter().any(|s| s.rule == "ransom.canary" || s.rule == "ransom.rename_burst");
        if strong && f.severity < Severity::High {
            f.severity = Severity::High;
        }
        let sev = f.severity;
        shared.watch_findings.write().push(f);
        {
            let mut g = shared.guard.write();
            g.canary.tripped = Some(now_ms());
            g.canary.last_alert = Some(detail.clone());
        }
        emit_event(
            app,
            shared,
            event(
                "ransom.alert",
                sev,
                "Fidye yazılımı davranışı algılandı".into(),
                format!("{detail}. Şüpheli işlemleri Tehdit ekranından askıya alın veya sonlandırın; ağ bağlantısını kesmeyi düşünün."),
                None,
                json!({ "pids": pids, "key": key }),
            ),
        );
        emit(app, shared);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_counts_only_document_renames_to_unknown_ext() {
        let mut b = Burst::default();
        let t = Instant::now();
        for i in 0..25 {
            b.rename(t, &format!(r"C:\d\{i}.docx"), &format!(r"C:\d\{i}.docx.locked"));
        }
        b.rename(t, r"C:\d\a.jpg", r"C:\d\a.jpeg"); // doc → doc: ignored
        b.rename(t, r"C:\d\a.tmp", r"C:\d\a.xyz"); // not a document: ignored
        let (r, w, _) = b.counts(t);
        assert_eq!((r, w), (25, 0));
        // Old events slide out of the window.
        let (r, _, _) = b.counts(t + WINDOW + Duration::from_secs(1));
        assert_eq!(r, 0);
    }

    #[test]
    fn build_folders_are_ignored() {
        assert!(noisy(r"C:\Users\u\Desktop\proj\node_modules\x\a.json"));
        assert!(noisy(r"C:\Users\u\Desktop\proj\src-tauri\target\release\a.pdf"));
        assert!(!noisy(r"C:\Users\u\Documents\fatura.pdf"));
    }

    #[test]
    fn decoy_content_is_stable() {
        assert_eq!(sha(&content(NAMES[0])), sha(&content(NAMES[0])));
        assert!(content(NAMES[1]).len() >= 4096);
    }
}
