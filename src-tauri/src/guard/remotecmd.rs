//! Acting from the phone: Telegram alert buttons (freeze / block / resume) and the weekly
//! summary on Sunday evening.
//!
//! Button presses are read with long-polling `getUpdates` (no webhook, no open port). A
//! press is honoured only from the configured chat and only for an alert this run of Ghost
//! Monitor sent (tokens live in memory). Blocking needs administrator rights: without them a
//! UAC prompt would wait on a screen nobody is looking at, so the reply says so instead.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{Datelike, Duration as CDuration, Local, TimeZone};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tauri::AppHandle;

use super::now_ms;
use super::remote::{send_text, telegram_creds};
use crate::model::{SecurityEvent, Severity};
use crate::monitor::{emit_event, event};
use crate::state::Shared;

const WEEKLY_KEY: &str = "remote_weekly_sent";
const MAX_TARGETS: usize = 300;

#[derive(Clone)]
struct Target {
    title: String,
    pids: Vec<u32>,
    exe: Option<String>,
    created: i64,
}

static TARGETS: Mutex<Option<HashMap<String, Target>>> = Mutex::new(None);

fn token() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!("{:x}{:03x}", (now_ms() / 1000) & 0xffffff, n & 0xfff)
}

fn exe_of(e: &SecurityEvent) -> Option<String> {
    let from_data = e.data.get("exe").and_then(Value::as_str).map(str::to_string);
    from_data.or_else(|| e.subject.clone()).filter(|p| std::path::Path::new(p).is_absolute() && p.to_ascii_lowercase().ends_with(".exe"))
}

fn pids_of(e: &SecurityEvent) -> Vec<u32> {
    let mut v: Vec<u32> = e.data.get("pids").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_u64()).map(|x| x as u32).collect()).unwrap_or_default();
    if let Some(p) = e.data.get("pid").and_then(Value::as_u64) {
        if !v.contains(&(p as u32)) {
            v.push(p as u32);
        }
    }
    v
}

/// Inline keyboard for an alert, when there is something to act on.
pub fn buttons_for(shared: &Shared, e: &SecurityEvent) -> Option<Value> {
    telegram_creds(shared)?;
    let exe = exe_of(e);
    let pids = pids_of(e);
    if exe.is_none() && pids.is_empty() {
        return None;
    }
    let tok = token();
    let mut row = vec![];
    if !pids.is_empty() || exe.is_some() {
        row.push(json!({ "text": "⏸ Dondur", "callback_data": format!("gm:{tok}:f") }));
    }
    if exe.is_some() {
        row.push(json!({ "text": "🚫 İnterneti kes", "callback_data": format!("gm:{tok}:b") }));
    }
    let mut g = TARGETS.lock();
    let map = g.get_or_insert_with(HashMap::new);
    if map.len() >= MAX_TARGETS {
        let cutoff = now_ms() - 24 * 3600_000;
        map.retain(|_, t| t.created > cutoff);
        if map.len() >= MAX_TARGETS {
            map.clear();
        }
    }
    map.insert(tok, Target { title: e.title.clone(), pids, exe, created: now_ms() });
    Some(json!({ "inline_keyboard": [row] }))
}

fn live_pids(shared: &Shared, t: &Target) -> Vec<(u32, String)> {
    let exe = t.exe.as_deref().map(str::to_ascii_lowercase);
    shared
        .processes
        .read()
        .iter()
        .filter(|p| match &exe {
            Some(x) => p.exe.as_deref().map(str::to_ascii_lowercase).as_deref() == Some(x.as_str()),
            None => t.pids.contains(&p.pid),
        })
        .map(|p| (p.pid, p.name.clone()))
        .collect()
}

/// Run a pressed button. Returns (short toast, message, follow-up keyboard).
fn act(app: &AppHandle, shared: &Shared, tok: &str, action: &str) -> (String, String, Option<Value>) {
    let Some(t) = TARGETS.lock().as_ref().and_then(|m| m.get(tok).cloned()) else {
        return ("Düğme geçersiz".into(), "Bu uyarı Ghost Monitor yeniden başlamadan önce gönderilmiş; düğmesi artık geçerli değil.".into(), None);
    };
    let host = shared.host.read().hostname.clone();
    match action {
        "f" | "r" => {
            let freeze = action == "f";
            let procs = live_pids(shared, &t);
            if procs.is_empty() {
                return ("Çalışmıyor".into(), format!("{}: ilgili program şu an çalışmıyor.", t.title), None);
            }
            let mut ok = 0;
            let mut last_err = String::new();
            for (pid, _) in &procs {
                match crate::commands_guard::suspend_pid(shared, *pid, freeze) {
                    Ok(_) => ok += 1,
                    Err(e) => last_err = e,
                }
            }
            let name = procs[0].1.clone();
            let verb = if freeze { "donduruldu" } else { "devam ettirildi" };
            let msg = if ok > 0 {
                format!("👻 {host}: {name} için {ok} işlem {verb} (telefondan).")
            } else {
                format!("👻 {host}: {name} {}: {last_err}", if freeze { "dondurulamadı" } else { "devam ettirilemedi" })
            };
            if ok > 0 {
                emit_event(
                    app,
                    shared,
                    event("remote.action", Severity::Low, format!("Telefondan: {name} {verb}"), t.title.clone(), t.exe.clone(), json!({ "action": action, "count": ok })),
                );
            }
            let follow = (ok > 0 && freeze).then(|| json!({ "inline_keyboard": [[{ "text": "▶ Devam ettir", "callback_data": format!("gm:{tok}:r") }]] }));
            (if ok > 0 { verb.to_string() } else { "Başarısız".into() }, msg, follow)
        }
        "b" => {
            let Some(exe) = t.exe.clone() else { return ("Program yok".into(), "Bu uyarıda engellenecek bir program yolu yok.".into(), None) };
            if !crate::winapi::elevation::is_elevated() {
                return (
                    "Yönetici yetkisi gerekiyor".into(),
                    format!("👻 {host}: Ghost Monitor yönetici olarak çalışmadığı için güvenlik duvarı kuralı telefondan eklenemiyor (Windows onayı bilgisayar ekranında beklerdi). Dondurmayı kullanabilir ya da bilgisayara dönünce Tehdit ekranından engelleyebilirsiniz."),
                    None,
                );
            }
            match super::firewall::block(shared, "program", &exe) {
                Ok(rule) => {
                    emit_event(
                        app,
                        shared,
                        event("user.block", Severity::Info, format!("Telefondan engellendi: {}", rule.target), "Gelen ve giden bağlantılar engellendi".into(), Some(rule.target.clone()), json!({ "rule": rule.name, "kind": rule.kind, "remote": true })),
                    );
                    ("İnternet kesildi".into(), format!("👻 {host}: {exe} artık internete çıkamıyor. Kuralı Sağlık → Engellenenler'den kaldırabilirsiniz."), None)
                }
                Err(e) => ("Başarısız".into(), format!("👻 {host}: engellenemedi: {e}"), None),
            }
        }
        _ => ("Bilinmeyen".into(), "Bilinmeyen komut.".into(), None),
    }
}

fn chat_matches(configured: &str, chat: &Value) -> bool {
    if let Some(u) = configured.strip_prefix('@') {
        chat.get("username").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case(u))
    } else {
        chat.get("id").map(|v| v.to_string()) == Some(configured.to_string())
    }
}

fn tg(token: &str, method: &str, body: Value, timeout: u64) -> Option<Value> {
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(timeout))).build().into();
    let url = format!("https://api.telegram.org/bot{token}/{method}");
    let mut r = agent.post(&url).header("Content-Type", "application/json").send(body.to_string()).ok()?;
    let text = r.body_mut().read_to_string().ok()?;
    serde_json::from_str(&text).ok()
}

fn poll_once(app: &AppHandle, shared: &Shared, offset: &mut i64) -> bool {
    let Some((token, chat)) = telegram_creds(shared) else { return false };
    let Some(res) = tg(&token, "getUpdates", json!({ "offset": *offset, "timeout": 25, "allowed_updates": ["callback_query"] }), 40) else {
        return false;
    };
    let Some(updates) = res.get("result").and_then(Value::as_array) else { return false };
    for u in updates {
        if let Some(id) = u.get("update_id").and_then(Value::as_i64) {
            *offset = (*offset).max(id + 1);
        }
        let Some(cb) = u.get("callback_query") else { continue };
        let cb_id = cb.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        let msg_chat = cb.pointer("/message/chat").cloned().unwrap_or(Value::Null);
        if !chat_matches(&chat, &msg_chat) {
            let _ = tg(&token, "answerCallbackQuery", json!({ "callback_query_id": cb_id, "text": "Yetkisiz" }), 15);
            continue;
        }
        let data = cb.get("data").and_then(Value::as_str).unwrap_or_default();
        let mut parts = data.split(':');
        let (Some("gm"), Some(tok), Some(action)) = (parts.next(), parts.next(), parts.next()) else { continue };
        let (toast, text, markup) = act(app, shared, tok, action);
        let _ = tg(&token, "answerCallbackQuery", json!({ "callback_query_id": cb_id, "text": toast }), 15);
        let mut body = json!({ "chat_id": chat, "text": text, "disable_web_page_preview": true });
        if let Some(m) = markup {
            body["reply_markup"] = m;
        }
        let _ = tg(&token, "sendMessage", body, 15);
    }
    true
}

/// The most recent Sunday 20:00 (local) that has passed.
fn last_slot(now: chrono::DateTime<Local>) -> chrono::DateTime<Local> {
    let days_back = now.weekday().num_days_from_sunday() as i64;
    let sunday = now.date_naive() - CDuration::days(days_back);
    let slot = Local.from_local_datetime(&sunday.and_hms_opt(20, 0, 0).unwrap()).earliest().unwrap_or(now);
    if slot > now { slot - CDuration::days(7) } else { slot }
}

pub fn weekly_text(shared: &Shared) -> String {
    let d = crate::weekly::build(&shared.store.lock().conn, now_ms());
    let host = shared.host.read().hostname.clone();
    let mut s = format!("👻 Ghost Monitor ({host}) — haftalık özet\n");
    if let Some(n) = d.health.now {
        match d.health.then {
            Some(t) if t != n => s.push_str(&format!("Sağlık puanı: {n} (geçen hafta {t}, {}{})\n", if n > t { "+" } else { "" }, n - t)),
            _ => s.push_str(&format!("Sağlık puanı: {n}\n")),
        }
    }
    let mut any = false;
    for sec in &d.sections {
        if sec.now == 0 {
            continue;
        }
        any = true;
        s.push_str(&format!("• {}: {} (geçen hafta {})\n", sec.title, sec.now, sec.prev));
        if sec.id == "findings" {
            for it in sec.items.iter().take(3) {
                s.push_str(&format!("   – {}\n", it.title));
            }
        }
    }
    if !any {
        s.push_str("Bu hafta kayda değer bir değişiklik olmadı.\n");
    }
    s.push_str("Ayrıntılar: Sağlık → Haftalık fark");
    s
}

fn weekly_due(shared: &Shared) {
    let set = shared.settings.read().clone();
    if !set.remote_notify || !set.remote_weekly {
        return;
    }
    let now = Local::now();
    let slot = last_slot(now);
    // A PC that was off on Sunday evening still gets it the next day, not a week later.
    if now - slot > CDuration::hours(36) {
        return;
    }
    let id = slot.format("%Y-%m-%d").to_string();
    if shared.store.lock().setting(WEEKLY_KEY).ok().flatten().as_deref() == Some(id.as_str()) {
        return;
    }
    let text = weekly_text(shared);
    match send_text(shared, &text) {
        Ok(_) => {
            let _ = shared.store.lock().set_setting(WEEKLY_KEY, &id);
        }
        Err(e) => log::warn!("weekly remote summary: {e}"),
    }
}

pub fn spawn(app: AppHandle, shared: std::sync::Arc<Shared>) {
    std::thread::Builder::new()
        .name("remotecmd".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(20));
            let mut offset: i64 = 0;
            let mut last_weekly = std::time::Instant::now() - Duration::from_secs(3600);
            loop {
                if last_weekly.elapsed() > Duration::from_secs(600) {
                    last_weekly = std::time::Instant::now();
                    weekly_due(&shared);
                }
                let s = shared.settings.read().clone();
                let polled = s.remote_notify && s.remote_actions && poll_once(&app, &shared, &mut offset);
                if !polled {
                    std::thread::sleep(Duration::from_secs(30));
                }
            }
        })
        .expect("spawn remotecmd");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sunday_slot() {
        let mon = Local.with_ymd_and_hms(2026, 11, 23, 9, 0, 0).unwrap(); // Monday
        assert_eq!(last_slot(mon).format("%Y-%m-%d %H").to_string(), "2026-11-22 20");
        let sun_early = Local.with_ymd_and_hms(2026, 11, 22, 19, 0, 0).unwrap();
        assert_eq!(last_slot(sun_early).format("%Y-%m-%d").to_string(), "2026-11-15");
        let sun_late = Local.with_ymd_and_hms(2026, 11, 22, 21, 0, 0).unwrap();
        assert_eq!(last_slot(sun_late).format("%Y-%m-%d").to_string(), "2026-11-22");
    }

    #[test]
    fn chat_check() {
        assert!(chat_matches("12345", &json!({ "id": 12345 })));
        assert!(!chat_matches("12345", &json!({ "id": 999 })));
        assert!(chat_matches("@kanal", &json!({ "id": -100, "username": "Kanal" })));
    }
}
