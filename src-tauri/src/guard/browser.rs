//! Browser extension audit for Chromium browsers (Chrome, Edge, Brave, Opera, Opera GX,
//! Vivaldi) and Firefox. Read-only: manifests and profile preference files.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Value};
use tauri::AppHandle;

use super::{emit, finding, now_ms, set_findings, severity_of};
use crate::engine::rules::sig;
use crate::model::{Severity, Signal};
use crate::monitor::{emit_event, event};
use crate::state::Shared;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Extension {
    pub key: String,
    pub browser: String,
    pub profile: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub from_store: bool,
    pub permissions: Vec<String>,
    pub path: String,
    pub signals: Vec<Signal>,
    pub severity: Severity,
}

/// Permission → (rule, label, weight). Combined they describe what an extension can do.
const RISKY: &[(&str, &str, &str, u32)] = &[
    ("<all_urls>", "ext.all_sites", "Tüm sitelerdeki verileri okuyup değiştirebilir", 20),
    ("*://*/*", "ext.all_sites", "Tüm sitelerdeki verileri okuyup değiştirebilir", 20),
    ("http://*/*", "ext.all_sites", "Tüm sitelerdeki verileri okuyup değiştirebilir", 20),
    ("https://*/*", "ext.all_sites", "Tüm sitelerdeki verileri okuyup değiştirebilir", 20),
    ("cookies", "ext.cookies", "Çerezleri okuyabilir (oturum çalma riski)", 15),
    ("debugger", "ext.debugger", "Sayfalara hata ayıklayıcı olarak bağlanabilir", 30),
    ("nativeMessaging", "ext.native", "Bilgisayardaki programlarla konuşabilir", 15),
    ("proxy", "ext.proxy", "Tarayıcının trafiğini başka sunucuya yönlendirebilir", 20),
    ("webRequestBlocking", "ext.webrequest", "Ağ isteklerini yakalayıp değiştirebilir", 10),
    ("declarativeNetRequestWithHostAccess", "ext.webrequest", "Ağ isteklerini yakalayıp değiştirebilir", 10),
    ("management", "ext.management", "Diğer uzantıları yönetebilir", 10),
    ("clipboardRead", "ext.clipboard", "Panoyu okuyabilir", 10),
    ("history", "ext.history", "Tarama geçmişini okuyabilir", 5),
];

fn chromium_roots() -> Vec<(String, PathBuf, bool)> {
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let roaming = std::env::var("APPDATA").unwrap_or_default();
    let l = |p: &str| PathBuf::from(&local).join(p);
    let r = |p: &str| PathBuf::from(&roaming).join(p);
    // (browser, user-data dir, profile dir is the root itself)
    vec![
        ("Chrome".into(), l(r"Google\Chrome\User Data"), false),
        ("Edge".into(), l(r"Microsoft\Edge\User Data"), false),
        ("Brave".into(), l(r"BraveSoftware\Brave-Browser\User Data"), false),
        ("Vivaldi".into(), l(r"Vivaldi\User Data"), false),
        ("Opera".into(), r(r"Opera Software\Opera Stable"), true),
        ("Opera GX".into(), r(r"Opera Software\Opera GX Stable"), true),
    ]
}

fn profiles(root: &Path, single: bool) -> Vec<PathBuf> {
    if single {
        return if root.join("Extensions").is_dir() { vec![root.to_path_buf()] } else { vec![] };
    }
    std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("Extensions").is_dir())
        .collect()
}

fn read_json(p: &Path) -> Option<Value> {
    let b = std::fs::read(p).ok()?;
    let b = b.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(&b);
    serde_json::from_slice(b).ok()
}

/// Resolve "__MSG_appName__" through _locales/<default>/messages.json.
fn localized(dir: &Path, manifest: &Value, raw: &str) -> String {
    let Some(key) = raw.strip_prefix("__MSG_").and_then(|s| s.strip_suffix("__")) else {
        return raw.to_string();
    };
    let default = manifest.get("default_locale").and_then(Value::as_str).unwrap_or("en");
    for loc in [default, "tr", "en", "en_US"] {
        if let Some(m) = read_json(&dir.join("_locales").join(loc).join("messages.json")) {
            let hit = m.as_object().and_then(|o| o.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)));
            if let Some(msg) = hit.and_then(|(_, v)| v.get("message")).and_then(Value::as_str) {
                return msg.to_string();
            }
        }
    }
    raw.to_string()
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

pub fn permission_signals(perms: &[String], from_store: bool, unpacked: bool) -> Vec<Signal> {
    let mut out: Vec<Signal> = Vec::new();
    let mut seen = HashSet::new();
    for p in perms {
        // Scoped host patterns like "*://*.example.com/*" don't match; only true wildcards do.
        let hit = RISKY.iter().find(|(k, ..)| p == k).or_else(|| p.starts_with("*://*/").then(|| &RISKY[0]));
        if let Some((_, rule, label, w)) = hit {
            if seen.insert(*rule) {
                out.push(sig(rule, label, *w, p.clone()));
            }
        }
    }
    if unpacked {
        out.push(sig("ext.unpacked", "Geliştirici modunda yüklenmiş (mağazadan değil)", 25, "paketlenmemiş uzantı"));
    } else if !from_store {
        out.push(sig("ext.sideloaded", "Resmi mağaza dışından yüklenmiş", 20, "mağaza dışı kurulum"));
    }
    out
}

fn chromium_settings(profile: &Path) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    for f in ["Secure Preferences", "Preferences"] {
        if let Some(v) = read_json(&profile.join(f)) {
            if let Some(o) = v.pointer("/extensions/settings").and_then(Value::as_object) {
                for (k, s) in o {
                    out.entry(k.clone()).or_insert_with(|| s.clone());
                }
            }
        }
    }
    out
}

fn scan_chromium(browser: &str, profile: &Path) -> Vec<Extension> {
    let settings = chromium_settings(profile);
    let pname = profile.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut out = Vec::new();
    let mut ids: HashSet<String> = HashSet::new();
    // Installed packages live under Extensions/<id>/<version>/; unpacked ones only in prefs.
    for e in std::fs::read_dir(profile.join("Extensions")).into_iter().flatten().flatten() {
        let id = e.file_name().to_string_lossy().into_owned();
        let Some(ver_dir) = std::fs::read_dir(e.path()).into_iter().flatten().flatten().map(|v| v.path()).filter(|p| p.join("manifest.json").exists()).max() else {
            continue;
        };
        ids.insert(id.clone());
        out.extend(build(browser, &pname, &id, &ver_dir, settings.get(&id)));
    }
    for (id, s) in &settings {
        if ids.contains(id) {
            continue;
        }
        if let Some(p) = s.get("path").and_then(Value::as_str) {
            let dir = PathBuf::from(p);
            if dir.is_absolute() && dir.join("manifest.json").exists() {
                out.extend(build(browser, &pname, id, &dir, Some(s)));
            }
        }
    }
    out
}

fn build(browser: &str, profile: &str, id: &str, dir: &Path, setting: Option<&Value>) -> Option<Extension> {
    let m = read_json(&dir.join("manifest.json"))?;
    // Built-in component extensions (location 5/10) are part of the browser.
    let location = setting.and_then(|s| s.get("location")).and_then(Value::as_i64).unwrap_or(1);
    if matches!(location, 5 | 10) || m.get("theme").is_some() {
        return None;
    }
    let name = localized(dir, &m, m.get("name").and_then(Value::as_str).unwrap_or(id));
    let mut perms = strings(m.get("permissions"));
    perms.extend(strings(m.get("host_permissions")));
    perms.extend(strings(m.get("optional_host_permissions")).into_iter().filter(|p| p == "<all_urls>"));
    if let Some(cs) = m.get("content_scripts").and_then(Value::as_array) {
        for c in cs {
            perms.extend(strings(c.get("matches")));
        }
    }
    perms.sort();
    perms.dedup();
    let from_store = setting.and_then(|s| s.get("from_webstore")).and_then(Value::as_bool).unwrap_or(false)
        || m.get("update_url").and_then(Value::as_str).is_some_and(|u| {
            u.contains("clients2.google.com") || u.contains("edge.microsoft.com") || u.contains("extension-updates.opera.com")
        });
    let unpacked = location == 4;
    // disable_reasons present and non-empty → disabled; state 0 → disabled on older builds
    let enabled = setting.is_none_or(|s| {
        let reasons = s.get("disable_reasons").map(|v| v.as_array().map_or(v.as_i64().unwrap_or(0) != 0, |a| !a.is_empty())).unwrap_or(false);
        let state = s.get("state").and_then(Value::as_i64).unwrap_or(1);
        !reasons && state != 0
    });
    let signals = permission_signals(&perms, from_store, unpacked);
    Some(Extension {
        key: format!("ext:{}:{}:{}", browser.to_ascii_lowercase().replace(' ', ""), profile.to_ascii_lowercase(), id),
        browser: browser.into(),
        profile: profile.into(),
        id: id.into(),
        name,
        version: m.get("version").and_then(Value::as_str).unwrap_or("").into(),
        enabled,
        from_store,
        permissions: perms,
        path: dir.display().to_string(),
        severity: severity_of(&signals),
        signals,
    })
}

fn scan_firefox() -> Vec<Extension> {
    let base = PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join(r"Mozilla\Firefox\Profiles");
    let mut out = Vec::new();
    for p in std::fs::read_dir(base).into_iter().flatten().flatten() {
        let Some(v) = read_json(&p.path().join("extensions.json")) else { continue };
        let pname = p.file_name().to_string_lossy().into_owned();
        for a in v.get("addons").and_then(Value::as_array).into_iter().flatten() {
            if a.get("type").and_then(Value::as_str) != Some("extension") || a.get("location").and_then(Value::as_str) != Some("app-profile") {
                continue;
            }
            let id = a.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            let mut perms = strings(a.pointer("/userPermissions/permissions"));
            perms.extend(strings(a.pointer("/userPermissions/origins")));
            let signed = a.get("signedState").and_then(Value::as_i64).unwrap_or(0) >= 2;
            let signals = permission_signals(&perms, signed, false);
            out.push(Extension {
                key: format!("ext:firefox:{}:{}", pname.to_ascii_lowercase(), id),
                browser: "Firefox".into(),
                profile: pname.clone(),
                name: a.pointer("/defaultLocale/name").and_then(Value::as_str).unwrap_or(&id).into(),
                version: a.get("version").and_then(Value::as_str).unwrap_or("").into(),
                enabled: a.get("active").and_then(Value::as_bool).unwrap_or(true),
                from_store: signed,
                path: a.get("path").and_then(Value::as_str).unwrap_or("").into(),
                id,
                permissions: perms,
                severity: severity_of(&signals),
                signals,
            });
        }
    }
    out
}

pub fn scan() -> Vec<Extension> {
    let mut v = Vec::new();
    for (browser, root, single) in chromium_roots() {
        for p in profiles(&root, single) {
            v.extend(scan_chromium(&browser, &p));
        }
    }
    v.extend(scan_firefox());
    v.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.browser.cmp(&b.browser)).then(a.name.cmp(&b.name)));
    v
}

pub fn tick(app: &AppHandle, shared: &Shared) {
    let exts = scan();
    // New-extension detection against the stored inventory (first scan = baseline).
    let st = shared.store.lock();
    let known: Option<HashSet<String>> = st.setting("ext_seen").ok().flatten().and_then(|v| serde_json::from_str(&v).ok());
    let now_keys: HashSet<String> = exts.iter().map(|e| e.key.clone()).collect();
    let _ = st.set_setting("ext_seen", &serde_json::to_string(&now_keys).unwrap_or_default());
    drop(st);
    let fresh: HashSet<String> = known.map(|k| now_keys.difference(&k).cloned().collect()).unwrap_or_default();

    let mut findings = Vec::new();
    for e in &exts {
        let mut signals = e.signals.clone();
        if fresh.contains(&e.key) {
            signals.push(sig("ext.new", "Yeni yüklenen uzantı", 10, format!("{} · {}", e.browser, e.profile)));
            emit_event(
                app,
                shared,
                event(
                    "browser.extension_new",
                    if e.severity >= Severity::Medium { Severity::Medium } else { Severity::Low },
                    format!("{} tarayıcısına yeni uzantı: {}", e.browser, e.name),
                    if e.signals.is_empty() { "Belirgin riskli izin yok.".into() } else { e.signals.iter().map(|s| s.label.clone()).collect::<Vec<_>>().join(" · ") },
                    Some(e.name.clone()),
                    json!({ "key": e.key, "id": e.id, "browser": e.browser }),
                ),
            );
        }
        // Only enabled extensions whose permissions add up to MEDIUM+ become findings.
        if e.enabled && severity_of(&signals) >= Severity::Medium {
            findings.extend(finding(&e.key, "extension", &e.path, format!("Riskli tarayıcı uzantısı: {} ({})", e.name, e.browser), signals, vec![]));
        }
    }
    set_findings(shared, "ext:", findings);
    {
        let mut g = shared.guard.write();
        g.extensions = exts;
        g.extensions_scanned = Some(now_ms());
    }
    emit(app, shared);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_score() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let quiet = permission_signals(&s(&["storage", "*://*.youtube.com/*"]), true, false);
        assert!(quiet.is_empty(), "{quiet:?}");
        let loud = permission_signals(&s(&["<all_urls>", "cookies", "nativeMessaging", "debugger"]), false, false);
        assert!(severity_of(&loud) >= Severity::High, "{loud:?}");
        let dev = permission_signals(&s(&[]), false, true);
        assert_eq!(dev[0].rule, "ext.unpacked");
    }

    #[test]
    fn live_scan_does_not_panic() {
        let v = scan();
        eprintln!("{} extensions", v.len());
        for e in v.iter().take(5) {
            eprintln!("{} | {} | {:?} | {}", e.browser, e.name, e.severity, e.permissions.len());
        }
    }
}
