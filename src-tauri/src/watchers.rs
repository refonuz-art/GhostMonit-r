//! Background jobs that are not part of the 1 Hz monitor loop:
//! - new executables in Downloads / Desktop are analysed as soon as they finish writing
//! - drives that appear (USB sticks, external disks, mounted ISOs) are inspected
//! - the MalwareBazaar hash list is refreshed daily (opt-in, needs an abuse.ch key)
//! - scheduled daily / weekly reports are written to disk

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use chrono::{Datelike, Local, NaiveTime, TimeZone};
use serde::Serialize;
use serde_json::json;
use tauri::AppHandle;

use crate::engine::{rules::sig, score};
use crate::intel::file::{self, FileReport};
use crate::model::{Finding, Severity, Signal};
use crate::monitor::{emit_event, event};
use crate::state::Shared;

const TICK: Duration = Duration::from_secs(3);
const MAX_ANALYZE_BYTES: u64 = 512 * 1024 * 1024;
const PARTIAL_EXT: &[&str] = &["crdownload", "part", "partial", "tmp", "download", "opdownload", "!ut"];
pub const ABUSE_SECRET: &str = "abusech_key";

/// Recent automatic analyses, shown in the File module.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoScan {
    pub ts: i64,
    pub origin: String,
    pub report: FileReport,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveInfo {
    pub letter: String,
    pub kind: String,
    pub label: String,
    pub fs: String,
    pub size: u64,
    pub since: i64,
    pub autorun: Option<String>,
    pub root_executables: Vec<String>,
    pub severity: Severity,
}

pub fn spawn(app: AppHandle, shared: Arc<Shared>) {
    std::thread::Builder::new()
        .name("watchers".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(6));
            let mut files = FileWatch::new(&shared);
            let mut drives = DriveWatch::new();
            let mut last_slow = Instant::now() - Duration::from_secs(3600);
            loop {
                let (fw, uw) = {
                    let s = shared.settings.read();
                    (s.file_watch, s.usb_watch)
                };
                if fw {
                    files.poll(&app, &shared);
                } else {
                    files.pause(&shared);
                }
                drives.poll(&app, &shared, uw);
                if last_slow.elapsed() > Duration::from_secs(60) {
                    last_slow = Instant::now();
                    maybe_update_feed(&app, &shared, false);
                    maybe_auto_report(&app, &shared);
                }
                std::thread::sleep(TICK);
            }
        })
        .expect("spawn watchers");
}

fn human_bytes(b: u64) -> String {
    let gb = b as f64 / 1_073_741_824.0;
    if gb >= 1.0 { format!("{gb:.0} GB") } else { format!("{} MB", b / 1_048_576) }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub(crate) fn set_finding(shared: &Shared, f: Option<Finding>, key: &str) {
    let mut w = shared.watch_findings.write();
    w.retain(|x| x.key != key);
    if let Some(f) = f {
        if !shared.store.lock().trusted().unwrap_or_default().iter().any(|k| k == key) {
            w.push(f);
        }
    }
}

fn analyze(shared: &Shared, path: &str) -> Result<FileReport, String> {
    file::analyze(path, |p| shared.sigs.verify_now(p), |h| crate::intel::hashdb::lookup(&shared.store.lock().conn, h))
}

fn record_scan(shared: &Shared, origin: &str, r: &FileReport) {
    let mut v = shared.auto_scans.write();
    v.retain(|s| s.report.path != r.path);
    v.insert(0, AutoScan { ts: now_ms(), origin: origin.into(), report: r.clone() });
    v.truncate(40);
}

// ------------------------------------------------------------------ files

pub fn known_folder(id: &windows::core::GUID) -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{SHGetKnownFolderPath, KNOWN_FOLDER_FLAG};
    unsafe {
        let p = SHGetKnownFolderPath(id, KNOWN_FOLDER_FLAG(0), None).ok()?;
        let s = p.to_string().ok();
        CoTaskMemFree(Some(p.0 as *const _));
        s.map(PathBuf::from)
    }
}

fn watched_folders() -> Vec<(PathBuf, &'static str)> {
    use windows::Win32::UI::Shell::{FOLDERID_Desktop, FOLDERID_Downloads};
    let mut v = Vec::new();
    if let Some(p) = known_folder(&FOLDERID_Downloads) {
        v.push((p, "İndirilenler"));
    }
    if let Some(p) = known_folder(&FOLDERID_Desktop) {
        v.push((p, "Masaüstü"));
    }
    v
}

/// Worth analysing: executable/script extension, or a PE header whatever the name says.
pub fn is_interesting(path: &Path) -> bool {
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if file::EXEC_EXT.contains(&ext.as_str()) {
        return true;
    }
    let mut head = [0u8; 2];
    use std::io::Read;
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut head)).is_ok() && &head == b"MZ"
}

struct Pending {
    size: u64,
    mtime: Option<SystemTime>,
}

struct FileWatch {
    folders: Vec<(PathBuf, &'static str)>,
    seen: HashSet<PathBuf>,
    pending: HashMap<PathBuf, Pending>,
    /// finding key → file path, to clear findings when the file is deleted
    flagged: HashMap<String, PathBuf>,
    last_mark: Instant,
    active: bool,
}

impl FileWatch {
    fn new(shared: &Shared) -> Self {
        let mut w = Self {
            folders: watched_folders(),
            seen: HashSet::new(),
            pending: HashMap::new(),
            flagged: HashMap::new(),
            last_mark: Instant::now(),
            active: false,
        };
        w.baseline(shared);
        w
    }

    /// Files older than the last time we were watching are not "new". Files written
    /// while the app was closed are still picked up on the next start.
    fn baseline(&mut self, shared: &Shared) {
        let since: Option<i64> = shared.store.lock().setting("file_watch_mark").ok().flatten().and_then(|v| v.parse().ok());
        let since = since.map(|ms| SystemTime::UNIX_EPOCH + Duration::from_millis(ms as u64));
        for (dir, _) in &self.folders {
            for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let m = e.metadata().ok();
                let newer = match (since, m.and_then(|m| m.modified().ok())) {
                    (Some(s), Some(t)) => t > s,
                    _ => false,
                };
                if !newer {
                    self.seen.insert(e.path());
                }
            }
        }
        self.mark(shared);
        self.active = true;
    }

    fn mark(&mut self, shared: &Shared) {
        let _ = shared.store.lock().set_setting("file_watch_mark", &now_ms().to_string());
        self.last_mark = Instant::now();
    }

    fn pause(&mut self, shared: &Shared) {
        if self.active {
            self.active = false;
            self.pending.clear();
            for k in self.flagged.keys() {
                set_finding(shared, None, k);
            }
            self.flagged.clear();
        }
    }

    fn poll(&mut self, app: &AppHandle, shared: &Shared) {
        if !self.active {
            // Re-enabled: don't report what arrived while the user had it switched off.
            self.seen.clear();
            let _ = shared.store.lock().set_setting("file_watch_mark", &now_ms().to_string());
            self.baseline(shared);
            return;
        }
        let mut ready = Vec::new();
        for (dir, origin) in &self.folders {
            let Ok(rd) = std::fs::read_dir(dir) else { continue };
            for e in rd.flatten() {
                let path = e.path();
                if self.seen.contains(&path) {
                    continue;
                }
                let Ok(m) = e.metadata() else { continue };
                if m.is_dir() {
                    self.seen.insert(path);
                    continue;
                }
                let ext = path.extension().map(|x| x.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                if PARTIAL_EXT.contains(&ext.as_str()) {
                    continue; // browser still downloading; the final name will appear later
                }
                let cur = Pending { size: m.len(), mtime: m.modified().ok() };
                match self.pending.get(&path) {
                    // Unchanged for one full tick → the writer is done.
                    Some(p) if p.size == cur.size && p.mtime == cur.mtime => {
                        self.pending.remove(&path);
                        self.seen.insert(path.clone());
                        ready.push((path, *origin, cur.size));
                    }
                    _ => {
                        self.pending.insert(path, cur);
                    }
                }
            }
        }
        self.pending.retain(|p, _| p.exists());
        for (path, origin, size) in ready {
            if is_interesting(&path) {
                self.inspect(app, shared, &path, origin, size);
            }
        }
        // Drop findings for files the user has since deleted.
        let gone: Vec<String> = self.flagged.iter().filter(|(_, p)| !p.exists()).map(|(k, _)| k.clone()).collect();
        for k in gone {
            self.flagged.remove(&k);
            set_finding(shared, None, &k);
        }
        if self.last_mark.elapsed() > Duration::from_secs(30) {
            self.mark(shared);
        }
    }

    fn inspect(&mut self, app: &AppHandle, shared: &Shared, path: &Path, origin: &str, size: u64) {
        let p = path.to_string_lossy().to_string();
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if size > MAX_ANALYZE_BYTES {
            emit_event(
                app,
                shared,
                event(
                    "file.new",
                    Severity::Info,
                    format!("{origin} klasörüne büyük dosya geldi: {name}"),
                    format!("{} MB — otomatik analiz için çok büyük; Dosya modülünden elle analiz edebilirsiniz.", size / 1_048_576),
                    Some(name),
                    json!({ "path": p, "origin": origin }),
                ),
            );
            return;
        }
        let r = match analyze(shared, &p) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("auto analyze {p}: {e}");
                return;
            }
        };
        record_scan(shared, origin, &r);
        let detail = if r.signals.is_empty() {
            match (&r.signature.publisher, r.signature.state) {
                (Some(pb), crate::model::SignatureState::Signed) => format!("İmzalı: {pb}. Belirgin risk sinyali yok."),
                _ => "Belirgin risk sinyali yok.".into(),
            }
        } else {
            r.signals.iter().map(|s| s.label.clone()).collect::<Vec<_>>().join(" · ")
        };
        let key = format!("file:{}", r.sha256);
        emit_event(
            app,
            shared,
            event(
                "file.new",
                r.severity,
                format!("{origin} klasörüne yeni dosya: {name}"),
                detail,
                Some(name.clone()),
                json!({ "path": p, "origin": origin, "sha256": r.sha256, "score": r.score, "key": key }),
            ),
        );
        if r.severity >= Severity::Medium {
            let now = now_ms();
            set_finding(
                shared,
                Some(Finding {
                    key: key.clone(),
                    entity_kind: "file".into(),
                    entity: p.clone(),
                    title: format!("Şüpheli dosya ({origin}): {name}"),
                    severity: r.severity,
                    score: r.score,
                    signals: r.signals.clone(),
                    first_seen: now,
                    last_seen: now,
                    pid: None,
                    pids: vec![],
                    status: "open".into(),
                }),
                &key,
            );
            self.flagged.insert(key, path.to_path_buf());
        }
    }
}

// ------------------------------------------------------------------ drives

#[link(name = "kernel32")]
extern "system" {
    fn GetLogicalDrives() -> u32;
    fn GetDriveTypeW(root: *const u16) -> u32;
}

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_CDROM: u32 = 5;

fn drive_kind(t: u32) -> Option<&'static str> {
    match t {
        DRIVE_REMOVABLE => Some("USB / çıkarılabilir"),
        DRIVE_FIXED => Some("harici disk"),
        DRIVE_CDROM => Some("optik / bağlanmış ISO"),
        _ => None,
    }
}

fn volume(root: &str) -> (String, String, u64) {
    use windows::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetVolumeInformationW};
    let w = crate::winapi::wide(root);
    let mut label = [0u16; 261];
    let mut fs = [0u16; 261];
    let mut total = 0u64;
    unsafe {
        let _ = GetVolumeInformationW(windows::core::PCWSTR(w.as_ptr()), Some(&mut label), None, None, None, Some(&mut fs));
        let _ = GetDiskFreeSpaceExW(windows::core::PCWSTR(w.as_ptr()), None, Some(&mut total), None);
    }
    let s = |b: &[u16]| String::from_utf16_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(0)]);
    (s(&label), s(&fs), total)
}

/// `open=` / `shellexecute=` / `shell\…\command=` lines of an autorun.inf.
pub fn autorun_command(inf: &str) -> Option<String> {
    inf.lines().map(str::trim).find_map(|l| {
        let (k, v) = l.split_once('=')?;
        let k = k.trim().to_ascii_lowercase();
        (k == "open" || k == "shellexecute" || (k.starts_with("shell\\") && k.ends_with("\\command")))
            .then(|| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

const SHELL_HOSTS: &[&str] = &["cmd.exe", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32"];

/// Root-of-drive heuristics (classic USB worm layout), independent of file analysis.
pub fn drive_signals(autorun: Option<&str>, lnks: &[(String, String)]) -> Vec<Signal> {
    let mut v = Vec::new();
    if let Some(cmd) = autorun {
        v.push(sig("usb.autorun", "autorun.inf bir program çalıştırmaya çalışıyor", 40, cmd));
    }
    for (name, target) in lnks {
        let t = target.to_ascii_lowercase();
        if SHELL_HOSTS.iter().any(|h| t.contains(h)) {
            v.push(sig("usb.lnk_shell", "Kök dizindeki kısayol komut yorumlayıcısı çalıştırıyor", 45, format!("{name} → {target}")));
        } else {
            v.push(sig("usb.lnk_root", "Sürücü kökünde kısayol (USB solucanlarının tipik izi)", 15, format!("{name} → {target}")));
        }
    }
    v
}

struct DriveWatch {
    known: Option<u32>,
}

impl DriveWatch {
    fn new() -> Self {
        Self { known: None }
    }

    fn poll(&mut self, app: &AppHandle, shared: &Shared, enabled: bool) {
        let mask = unsafe { GetLogicalDrives() };
        let Some(prev) = self.known.replace(mask) else { return }; // first poll = baseline
        if !enabled {
            shared.drives.write().clear();
            return;
        }
        for i in 0..26u32 {
            let bit = 1 << i;
            let letter = format!("{}:\\", (b'A' + i as u8) as char);
            if mask & bit != 0 && prev & bit == 0 {
                self.inserted(app, shared, &letter);
            } else if mask & bit == 0 && prev & bit != 0 {
                let had = {
                    let mut d = shared.drives.write();
                    let had = d.iter().any(|x| x.letter == letter);
                    d.retain(|x| x.letter != letter);
                    had
                };
                set_finding(shared, None, &format!("drive:{letter}"));
                if had {
                    emit_event(
                        app,
                        shared,
                        event("usb.removed", Severity::Info, format!("Sürücü çıkarıldı: {letter}"), String::new(), None, json!({ "letter": letter })),
                    );
                }
            }
        }
    }

    fn inserted(&mut self, app: &AppHandle, shared: &Shared, letter: &str) {
        let w = crate::winapi::wide(letter);
        let Some(kind) = drive_kind(unsafe { GetDriveTypeW(w.as_ptr()) }) else { return };
        // Media may need a moment to mount.
        std::thread::sleep(Duration::from_millis(800));
        let (label, fs, size) = volume(letter);

        let mut autorun = None;
        let mut lnks = Vec::new();
        let mut execs = Vec::new();
        for e in std::fs::read_dir(letter).into_iter().flatten().flatten().take(500) {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if e.metadata().map(|m| m.is_dir()).unwrap_or(true) {
                continue;
            }
            let lower = name.to_ascii_lowercase();
            if lower == "autorun.inf" {
                let txt = std::fs::read(&p).map(|b| String::from_utf8_lossy(&b[..b.len().min(65536)]).into_owned()).unwrap_or_default();
                autorun = autorun_command(&txt);
            } else if lower.ends_with(".lnk") {
                let (t, a) = crate::collectors::startup::resolve_lnk(&p.to_string_lossy()).unwrap_or_default();
                lnks.push((name, format!("{t} {a}").trim().to_string()));
            } else if is_interesting(&p) {
                execs.push(p);
            }
        }

        let mut signals = drive_signals(autorun.as_deref(), &lnks);
        let mut names = Vec::new();
        for p in execs.iter().take(10) {
            let size = p.metadata().map(|m| m.len()).unwrap_or(0);
            names.push(p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
            if size > 100 * 1024 * 1024 {
                continue;
            }
            if let Ok(r) = analyze(shared, &p.to_string_lossy()) {
                record_scan(shared, &format!("Sürücü {letter}"), &r);
                for mut s in r.signals {
                    s.evidence = format!("{}: {}", r.name, s.evidence);
                    signals.push(s);
                }
            }
        }
        let (score_v, sev) = score(&signals);
        let sev = if signals.is_empty() { Severity::Info } else { sev };
        let info = DriveInfo {
            letter: letter.into(),
            kind: kind.into(),
            label: if label.is_empty() { "etiketsiz".into() } else { label },
            fs,
            size,
            since: now_ms(),
            autorun: autorun.clone(),
            root_executables: names.clone(),
            severity: sev,
        };
        let detail = if signals.is_empty() {
            if names.is_empty() {
                "Kök dizinde çalıştırılabilir dosya yok.".into()
            } else {
                format!("Kök dizinde {} çalıştırılabilir dosya analiz edildi, sinyal yok.", names.len())
            }
        } else {
            signals.iter().map(|s| s.label.clone()).collect::<Vec<_>>().join(" · ")
        };
        emit_event(
            app,
            shared,
            event(
                "usb.inserted",
                sev,
                format!("Sürücü takıldı: {letter} {} ({}, {})", info.label, kind, human_bytes(size)),
                detail,
                Some(letter.to_string()),
                json!({ "letter": letter, "kind": kind, "label": info.label, "fs": info.fs, "size": size, "autorun": autorun, "executables": names }),
            ),
        );
        let key = format!("drive:{letter}");
        if sev >= Severity::Medium {
            let now = now_ms();
            set_finding(
                shared,
                Some(Finding {
                    key: key.clone(),
                    entity_kind: "drive".into(),
                    entity: letter.into(),
                    title: format!("Şüpheli sürücü: {letter} {}", info.label),
                    severity: sev,
                    score: score_v,
                    signals,
                    first_seen: now,
                    last_seen: now,
                    pid: None,
                    pids: vec![],
                    status: "open".into(),
                }),
                &key,
            );
        }
        let mut d = shared.drives.write();
        d.retain(|x| x.letter != letter);
        d.push(info);
    }
}

// ------------------------------------------------------------------ feed

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedResult {
    pub added: u64,
    pub seen: u64,
    pub total: i64,
}

pub fn update_feed(shared: &Shared) -> Result<FeedResult, String> {
    let key = crate::commands_intel::secret(shared, ABUSE_SECRET).ok_or("abuse.ch anahtarı tanımlı değil")?;
    let text = crate::intel::hashdb::fetch_bazaar(&key)?;
    let st = shared.store.lock();
    let (added, seen) = crate::intel::hashdb::import_bazaar_csv(&st.conn, &text)?;
    let total = crate::intel::hashdb::stats(&st.conn).map(|s| s.total).unwrap_or(0);
    let _ = st.set_setting("feed_last_ok", &now_ms().to_string());
    Ok(FeedResult { added, seen, total })
}

/// Daily, after a successful update; failed attempts retry at most every 2 hours.
fn maybe_update_feed(app: &AppHandle, shared: &Shared, force: bool) {
    if !force && !shared.settings.read().feed_auto_update {
        return;
    }
    let now = now_ms();
    let get = |k: &str| shared.store.lock().setting(k).ok().flatten().and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    if !force && (now - get("feed_last_ok") < 86_400_000 || now - get("feed_last_try") < 2 * 3_600_000) {
        return;
    }
    let _ = shared.store.lock().set_setting("feed_last_try", &now.to_string());
    let (sev, title, detail) = match update_feed(shared) {
        Ok(r) => (
            Severity::Info,
            format!("Kötü amaçlı yazılım listesi güncellendi: {} yeni", r.added),
            format!("MalwareBazaar son 48 saat: {} hash, {} tanesi yeni. Yerel veritabanında toplam {}.", r.seen, r.added, r.total),
        ),
        Err(e) => (Severity::Info, "Kötü amaçlı yazılım listesi güncellenemedi".to_string(), e),
    };
    emit_event(app, shared, event("intel.feed", sev, title, detail, None, json!({})));
}

// ------------------------------------------------------------------ scheduled reports

/// The most recent schedule boundary at or before `now` and the period it covers.
/// Daily: every day 00:05 → previous calendar day. Weekly: Monday 00:05 → previous Mon–Sun.
pub fn due_period<Tz: TimeZone>(kind: &str, now: chrono::DateTime<Tz>) -> Option<(i64, i64, i64)> {
    let tz = now.timezone();
    let at = NaiveTime::from_hms_opt(0, 5, 0)?;
    let mut day = now.date_naive();
    if now.time() < at {
        day = day.pred_opt()?;
    }
    let span_days = match kind {
        "daily" => 1,
        "weekly" => {
            day = day - chrono::Days::new(day.weekday().num_days_from_monday() as u64);
            7
        }
        _ => return None,
    };
    let start_of = |d: chrono::NaiveDate| tz.from_local_datetime(&d.and_hms_opt(0, 0, 0).unwrap()).earliest().map(|t| t.timestamp_millis());
    let due = tz.from_local_datetime(&day.and_time(at)).earliest()?.timestamp_millis();
    let until = start_of(day)?;
    let since = start_of(day - chrono::Days::new(span_days))?;
    Some((due, since, until))
}

fn report_dir(shared: &Shared) -> PathBuf {
    if let Some(d) = shared.settings.read().auto_report_dir.clone() {
        return PathBuf::from(d);
    }
    use windows::Win32::UI::Shell::FOLDERID_Documents;
    known_folder(&FOLDERID_Documents)
        .unwrap_or_else(|| PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default()))
        .join("Ghost Monitor Raporları")
}

fn maybe_auto_report(app: &AppHandle, shared: &Shared) {
    let (kind, fmt) = {
        let s = shared.settings.read();
        (s.auto_report.clone(), s.auto_report_format.clone())
    };
    let Some((due, since, until)) = due_period(&kind, Local::now()) else { return };
    let mark = format!("auto_report_{kind}");
    let last: i64 = shared.store.lock().setting(&mark).ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(0);
    if last >= due {
        return;
    }
    let dir = report_dir(shared);
    let day = |ms: i64| Local.timestamp_millis_opt(ms).single().map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default();
    let fname = match kind.as_str() {
        "daily" => format!("GhostMonitor_gunluk_{}.{fmt}", day(since)),
        _ => format!("GhostMonitor_haftalik_{}_{}.{fmt}", day(since), day(until - 1)),
    };
    let path = dir.join(fname);
    let res = std::fs::create_dir_all(&dir).map_err(|e| e.to_string()).and_then(|_| {
        let data = crate::report::build(shared, &kind, since, until)?;
        let p = path.to_string_lossy();
        if fmt == "json" {
            crate::report::write_json(&data, &p)
        } else {
            crate::report::write_pdf(&data, &p)
        }
    });
    // Mark as done even on failure so a broken folder doesn't retry every minute.
    let _ = shared.store.lock().set_setting(&mark, &due.to_string());
    let (title, detail) = match res {
        Ok(()) => (format!("Otomatik {} rapor yazıldı", if kind == "daily" { "günlük" } else { "haftalık" }), path.to_string_lossy().to_string()),
        Err(e) => ("Otomatik rapor yazılamadı".to_string(), format!("{}: {e}", path.display())),
    };
    emit_event(app, shared, event("report.auto", Severity::Info, title, detail, None, json!({ "path": path })));
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn autorun_parsing() {
        assert_eq!(autorun_command("[autorun]\r\nicon=a.ico\r\nopen=setup.exe /s\r\n").as_deref(), Some("setup.exe /s"));
        assert_eq!(autorun_command("[AutoRun]\nshell\\open\\command=evil.exe").as_deref(), Some("evil.exe"));
        assert_eq!(autorun_command("[autorun]\nicon=a.ico\nlabel=Disk"), None);
    }

    #[test]
    fn usb_worm_layout_scores() {
        let lnk = vec![("Belgeler.lnk".to_string(), r"C:\Windows\System32\cmd.exe /c start x.vbs".to_string())];
        let (_, sev) = score(&drive_signals(Some("x.exe"), &lnk));
        assert!(sev >= Severity::High, "{sev:?}");
        let (_, sev) = score(&drive_signals(None, &[("Kurulum.lnk".into(), r"E:\setup.exe".into())]));
        assert!(sev < Severity::Medium, "{sev:?}");
    }

    #[test]
    fn schedule_boundaries() {
        // Wednesday 2026-11-18 10:00 UTC
        let now = Utc.with_ymd_and_hms(2026, 11, 18, 10, 0, 0).unwrap();
        let (due, since, until) = due_period("daily", now).unwrap();
        assert_eq!(due, Utc.with_ymd_and_hms(2026, 11, 18, 0, 5, 0).unwrap().timestamp_millis());
        assert_eq!(since, Utc.with_ymd_and_hms(2026, 11, 17, 0, 0, 0).unwrap().timestamp_millis());
        assert_eq!(until, Utc.with_ymd_and_hms(2026, 11, 18, 0, 0, 0).unwrap().timestamp_millis());
        let (due, since, until) = due_period("weekly", now).unwrap();
        assert_eq!(due, Utc.with_ymd_and_hms(2026, 11, 16, 0, 5, 0).unwrap().timestamp_millis());
        assert_eq!(since, Utc.with_ymd_and_hms(2026, 11, 9, 0, 0, 0).unwrap().timestamp_millis());
        assert_eq!(until, Utc.with_ymd_and_hms(2026, 11, 16, 0, 0, 0).unwrap().timestamp_millis());
        // Before 00:05 the previous day's boundary still applies.
        let early = Utc.with_ymd_and_hms(2026, 11, 18, 0, 3, 0).unwrap();
        assert_eq!(due_period("daily", early).unwrap().2, Utc.with_ymd_and_hms(2026, 11, 17, 0, 0, 0).unwrap().timestamp_millis());
        assert!(due_period("off", now).is_none());
    }

    #[test]
    fn exe_named_as_pdf_is_interesting() {
        let dir = std::env::temp_dir().join("gm_watch_test");
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("fatura.pdf");
        std::fs::write(&fake, b"MZ\x90\x00").unwrap();
        let doc = dir.join("not.txt");
        std::fs::write(&doc, b"hello").unwrap();
        assert!(is_interesting(&fake));
        assert!(!is_interesting(&doc));
        assert!(is_interesting(Path::new("x.ps1")));
        let _ = std::fs::remove_dir_all(dir);
    }
}
