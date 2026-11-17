//! "Opera'yı aç": find a program by its Start Menu / Desktop shortcut name and start it.
//!
//! Only shortcuts that exist in the Start Menu or on the Desktop, plus a short list of
//! Windows tools, can be launched. The frontend never passes an arbitrary path to run:
//! `launch` re-scans and accepts only a path that is in the index.

use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppEntry {
    pub name: String,
    /// Shortcut path, or the builtin target (e.g. `calc.exe`, `ms-settings:`).
    pub target: String,
    pub score: u32,
}

/// Windows tools people ask for by their Turkish name.
const BUILTIN: &[(&str, &str)] = &[
    ("Hesap Makinesi", "calc.exe"),
    ("Not Defteri", "notepad.exe"),
    ("Görev Yöneticisi", "taskmgr.exe"),
    ("Denetim Masası", "control.exe"),
    ("Dosya Gezgini", "explorer.exe"),
    ("Paint", "mspaint.exe"),
    ("Komut İstemi", "cmd.exe"),
    ("Ayarlar", "ms-settings:"),
    ("Windows Güvenliği", "windowsdefender:"),
    ("Ekran Alıntısı Aracı", "ms-screenclip:"),
];

/// Lowercase with Turkish letters folded to ASCII; keeps letters, digits and spaces.
pub fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let c = match c {
            'İ' | 'I' | 'ı' | 'i' => 'i',
            'Ş' | 'ş' => 's',
            'Ğ' | 'ğ' => 'g',
            'Ü' | 'ü' => 'u',
            'Ö' | 'ö' => 'o',
            'Ç' | 'ç' => 'c',
            'Â' | 'â' => 'a',
            c => c.to_ascii_lowercase(),
        };
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with(' ') && !out.is_empty() {
            out.push(' ');
        }
    }
    out.trim_end().to_string()
}

fn compact(s: &str) -> String {
    s.chars().filter(|c| *c != ' ').collect()
}

/// How well `query` (already folded) names the program `name`. 0 = no match.
pub fn score(query: &str, name: &str) -> u32 {
    let n = fold(name);
    let (q, nc) = (compact(query), compact(&n));
    if q.len() < 2 || nc.is_empty() {
        return 0;
    }
    if q == nc {
        return 100;
    }
    // "operayi" / "chromeu" / "notdefterini": the name plus a Turkish case suffix.
    if nc.len() >= 3 && q.starts_with(&nc) && q.len() - nc.len() <= 4 {
        return 92 - (q.len() - nc.len()) as u32;
    }
    // "opera" for "Opera GX Browser": the query is the start of the name.
    if q.len() >= 3 && nc.starts_with(&q) {
        return 80 - ((nc.len() - q.len()).min(30) as u32);
    }
    let words: Vec<&str> = n.split(' ').collect();
    if q.len() >= 3 && words.iter().any(|w| w.starts_with(&q) || (w.len() >= 3 && q.starts_with(w) && q.len() - w.len() <= 4)) {
        return 60 - ((nc.len()).min(30) as u32 / 3);
    }
    0
}

fn start_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    if let Some(p) = env("ProgramData") {
        v.push(p.join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    if let Some(p) = env("APPDATA") {
        v.push(p.join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    if let Some(p) = env("USERPROFILE") {
        v.push(p.join("Desktop"));
        v.push(p.join("OneDrive").join("Desktop"));
    }
    if let Some(p) = env("PUBLIC") {
        v.push(p.join("Desktop"));
    }
    v
}

fn walk(dir: &Path, depth: u32, out: &mut Vec<(String, PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() && depth < 4 {
            walk(&p, depth + 1, out);
        } else if ft.is_file() {
            let ext = p.extension().map(|x| x.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
            if ext != "lnk" && ext != "url" {
                continue;
            }
            let name = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            let f = fold(&name);
            if f.contains("uninstall") || f.contains("kaldir") || f.contains("readme") || f.contains("help") {
                continue;
            }
            out.push((name, p));
        }
    }
}

/// Every launchable entry: (display name, target).
pub fn index() -> Vec<(String, String)> {
    let mut files = Vec::new();
    for d in start_dirs() {
        walk(&d, 0, &mut files);
    }
    let mut v: Vec<(String, String)> = BUILTIN.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect();
    v.extend(files.into_iter().map(|(n, p)| (n, p.to_string_lossy().to_string())));
    v
}

pub fn find(query: &str, limit: usize) -> Vec<AppEntry> {
    let q = fold(query);
    let mut hits: Vec<AppEntry> = index()
        .into_iter()
        .filter_map(|(name, target)| {
            let s = score(&q, &name);
            (s > 0).then_some(AppEntry { name, target, score: s })
        })
        .collect();
    hits.sort_by(|a, b| b.score.cmp(&a.score).then(a.name.len().cmp(&b.name.len())));
    hits.dedup_by(|a, b| fold(&a.name) == fold(&b.name));
    hits.truncate(limit);
    hits
}

fn shell_open(target: &str, verb_args: Option<&str>) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let file = crate::winapi::wide(target);
    let verb = crate::winapi::wide("open");
    let args = verb_args.map(crate::winapi::wide);
    let h = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            args.as_ref().map(|a| PCWSTR(a.as_ptr())).unwrap_or(PCWSTR::null()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute reports success with a value greater than 32.
    if h.0 as isize > 32 {
        Ok(())
    } else {
        Err(format!("Program başlatılamadı (kod {})", h.0 as isize))
    }
}

/// Start an indexed program. `target` must be exactly one returned by `find`.
pub fn launch(target: &str) -> Result<String, String> {
    let Some((name, t)) = index().into_iter().find(|(_, t)| t == target) else {
        return Err("Bu program listede yok".into());
    };
    shell_open(&t, None)?;
    Ok(name)
}

/// Open a web address in the default browser. Only plain https URLs.
pub fn open_url(url: &str) -> Result<(), String> {
    let ok = url.len() <= 2000
        && url.starts_with("https://")
        && !url.chars().any(|c| c.is_whitespace() || c == '"' || c.is_control())
        && url[8..].split('/').next().is_some_and(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'));
    if !ok {
        return Err("Yalnızca https adresleri açılabilir".into());
    }
    shell_open(url, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turkish_suffixes_match_program_names() {
        assert_eq!(fold("Opera'yı  AÇ!"), "opera yi ac");
        assert!(score(&fold("operayı"), "Opera") > 85);
        assert!(score(&fold("chrome'u"), "Google Chrome") > 0);
        assert!(score(&fold("not defterini"), "Not Defteri") > 85);
        assert!(score(&fold("hesap makinesini"), "Hesap Makinesi") > 85);
        assert!(score(&fold("opera"), "Opera GX Browser") > 50);
        assert_eq!(score(&fold("op"), "Notepad"), 0);
        assert_eq!(score(&fold("spotify"), "Steam"), 0);
        assert!(score(&fold("opera"), "Opera") > score(&fold("opera"), "Opera GX Browser"));
    }

    #[test]
    fn urls_are_restricted() {
        assert!(open_url("http://example.com").is_err());
        assert!(open_url("https://exa mple.com").is_err());
        assert!(open_url("https://\"evil").is_err());
        assert!(open_url("file:///C:/Windows").is_err());
    }
}
