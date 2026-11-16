//! Windows event log watcher (EvtQuery). Picks up account and defence events that the
//! process view cannot see: brute-force logons, new accounts, admin-group changes, cleared
//! logs, RDP logons, newly installed services and Defender detections.
//!
//! The Security channel is readable only by administrators; without elevation those rules
//! are reported as unavailable instead of silently showing nothing.

use std::collections::{HashMap, VecDeque};

use serde::Serialize;
use serde_json::json;
use tauri::AppHandle;
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtRender, EvtRenderEventXml, EVT_HANDLE, EvtQueryChannelPath, EvtQueryForwardDirection,
    EvtQueryReverseDirection,
};

use super::{finding, now_ms, set_findings};
use crate::engine::rules::sig;
use crate::model::Severity;
use crate::monitor::{emit_event, event};
use crate::state::Shared;

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogStatus {
    pub last_check: Option<i64>,
    pub channels: Vec<ChannelStatus>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStatus {
    pub name: String,
    pub label: String,
    pub readable: bool,
    pub needs_admin: bool,
}

const CHANNELS: &[(&str, &str, &str)] = &[
    ("Security", "Oturum açma ve hesaplar", "4625,4720,4732,4728,4756,1102,4624"),
    ("System", "Hizmet kurulumu, günlük temizleme", "7045,104"),
    ("Microsoft-Windows-Windows Defender/Operational", "Defender algılamaları", "1116,1117,5001,5007"),
];

#[derive(Debug, Clone, Default)]
pub struct Record {
    pub id: u32,
    pub record: u64,
    pub time: String,
    pub data: HashMap<String, String>,
}

/// Tiny extractor for the event XML (no namespaces needed, fields are flat).
pub fn parse_xml(x: &str) -> Record {
    let between = |a: &str, b: &str| -> Option<String> {
        let i = x.find(a)? + a.len();
        let j = x[i..].find(b)?;
        Some(x[i..i + j].to_string())
    };
    let id = between("<EventID", "</EventID>").and_then(|s| s.rsplit('>').next().and_then(|n| n.trim().parse().ok())).unwrap_or(0);
    let record = between("<EventRecordID>", "</EventRecordID>").and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let time = between("SystemTime='", "'").or_else(|| between("SystemTime=\"", "\"")).unwrap_or_default();
    let mut data = HashMap::new();
    let mut rest = x;
    while let Some(i) = rest.find("<Data Name=") {
        rest = &rest[i + 11..];
        let q = rest.chars().next().unwrap_or('\'');
        let Some(end_name) = rest[1..].find(q) else { break };
        let name = rest[1..1 + end_name].to_string();
        let after = &rest[1 + end_name + 1..];
        let value = if after.starts_with("/>") {
            String::new()
        } else {
            let v = after.trim_start_matches('>');
            v[..v.find("</Data>").unwrap_or(0)].to_string()
        };
        data.insert(name, unescape(&value));
    }
    Record { id, record, time, data }
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

struct Handle(EVT_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = EvtClose(self.0);
        }
    }
}

fn render(h: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut props = 0u32;
    unsafe {
        let _ = EvtRender(None, h, EvtRenderEventXml.0 as u32, 0, None, &mut used, &mut props);
        if used == 0 {
            return None;
        }
        let mut buf = vec![0u16; used as usize / 2 + 1];
        EvtRender(None, h, EvtRenderEventXml.0 as u32, (buf.len() * 2) as u32, Some(buf.as_mut_ptr() as *mut _), &mut used, &mut props).ok()?;
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..n]))
    }
}

/// Query a channel. Err(true) = access denied.
pub fn query(channel: &str, xpath: &str, newest_first: bool, max: usize) -> Result<Vec<Record>, bool> {
    let c = crate::winapi::wide(channel);
    let q = crate::winapi::wide(xpath);
    let dir = if newest_first { EvtQueryReverseDirection.0 } else { EvtQueryForwardDirection.0 };
    let rs = unsafe { EvtQuery(None, PCWSTR(c.as_ptr()), PCWSTR(q.as_ptr()), EvtQueryChannelPath.0 | dir) }
        .map_err(|e| e.code().0 as u32 == 0x80070005)?;
    let rs = Handle(rs);
    let mut out = Vec::new();
    while out.len() < max {
        let mut batch = [0isize; 32];
        let mut got = 0u32;
        if unsafe { EvtNext(rs.0, &mut batch, 1000, 0, &mut got) }.is_err() || got == 0 {
            break;
        }
        for raw in &batch[..got as usize] {
            let h = Handle(EVT_HANDLE(*raw));
            if let Some(x) = render(h.0) {
                out.push(parse_xml(&x));
            }
        }
    }
    Ok(out)
}

fn ids_xpath(ids: &str, after: u64) -> String {
    let cond = ids.split(',').map(|i| format!("EventID={i}")).collect::<Vec<_>>().join(" or ");
    format!("*[System[({cond}) and EventRecordID > {after}]]")
}

/// Failed-logon timestamps kept across ticks for the brute-force window.
static FAILS: parking_lot::Mutex<VecDeque<(i64, String)>> = parking_lot::const_mutex(VecDeque::new());
const FAIL_WINDOW_MS: i64 = 10 * 60 * 1000;

pub fn tick(app: &AppHandle, shared: &Shared) {
    let mut statuses = Vec::new();
    for (channel, label, ids) in CHANNELS {
        let key = format!("evt_last:{channel}");
        let last: Option<u64> = shared.store.lock().setting(&key).ok().flatten().and_then(|v| v.parse().ok());
        let res = match last {
            // First run: remember where the log is now; history is not replayed.
            None => query(channel, "*", true, 1).map(|v| {
                let top = v.first().map(|r| r.record).unwrap_or(0);
                let _ = shared.store.lock().set_setting(&key, &top.to_string());
                vec![]
            }),
            Some(after) => query(channel, &ids_xpath(ids, after), false, 500),
        };
        statuses.push(ChannelStatus {
            name: channel.to_string(),
            label: label.to_string(),
            readable: res.is_ok(),
            needs_admin: matches!(res, Err(true)),
        });
        let Ok(records) = res else { continue };
        if let Some(max) = records.iter().map(|r| r.record).max() {
            let _ = shared.store.lock().set_setting(&key, &max.to_string());
        }
        for r in records {
            handle(app, shared, channel, &r);
        }
    }
    brute_force(shared);
    let mut g = shared.guard.write();
    g.eventlog = EventLogStatus { last_check: Some(now_ms()), channels: statuses };
}

fn d<'a>(r: &'a Record, k: &str) -> &'a str {
    r.data.get(k).map(String::as_str).unwrap_or("")
}

fn handle(app: &AppHandle, shared: &Shared, channel: &str, r: &Record) {
    let ev = |kind: &str, sev: Severity, title: String, detail: String| {
        emit_event(app, shared, event(kind, sev, title, detail, None, json!({ "channel": channel, "eventId": r.id, "record": r.record, "time": r.time })));
    };
    let add_finding = |rule: &str, label: &str, w: u32, evidence: String, title: String| {
        let key = format!("evt:{}:{}", r.id, r.record);
        if let Some(f) = finding(&key, "account", channel, title, vec![sig(rule, label, w, evidence)], vec![]) {
            shared.watch_findings.write().push(f);
        }
    };
    match (channel, r.id) {
        ("Security", 4625) => {
            let who = format!("{}\\{} ← {}", d(r, "TargetDomainName"), d(r, "TargetUserName"), d(r, "IpAddress"));
            FAILS.lock().push_back((now_ms(), who));
        }
        ("Security", 4720) => {
            let user = format!("{}\\{}", d(r, "TargetDomainName"), d(r, "TargetUserName"));
            ev("account.created", Severity::Medium, format!("Yeni kullanıcı hesabı oluşturuldu: {user}"), format!("oluşturan: {}", d(r, "SubjectUserName")));
            add_finding("evt.user_created", "Yeni kullanıcı hesabı oluşturuldu", 40, user.clone(), format!("Yeni kullanıcı hesabı: {user}"));
        }
        ("Security", 4732 | 4728 | 4756) if d(r, "TargetSid").ends_with("-544") || d(r, "TargetUserName").to_ascii_lowercase().contains("admin") => {
            let member = if d(r, "MemberName").is_empty() || d(r, "MemberName") == "-" { d(r, "MemberSid") } else { d(r, "MemberName") };
            ev("account.admin", Severity::High, format!("Yöneticiler grubuna üye eklendi: {member}"), format!("ekleyen: {}", d(r, "SubjectUserName")));
            add_finding("evt.admin_added", "Bir hesap yönetici yapıldı", 50, member.to_string(), "Yöneticiler grubuna yeni üye".into());
        }
        ("Security", 1102) | ("System", 104) => {
            ev("log.cleared", Severity::High, "Windows olay günlüğü temizlendi".into(), format!("{channel} günlüğü · {}", d(r, "SubjectUserName")));
            add_finding("evt.log_cleared", "Olay günlüğü temizlendi (iz silme)", 50, channel.to_string(), "Olay günlüğü temizlendi".into());
        }
        ("Security", 4624) if d(r, "LogonType") == "10" => {
            ev(
                "account.rdp",
                Severity::Low,
                format!("Uzak masaüstü oturumu açıldı: {}", d(r, "TargetUserName")),
                format!("kaynak: {} ({})", d(r, "IpAddress"), d(r, "WorkstationName")),
            );
        }
        ("System", 7045) => {
            let image = d(r, "ImagePath").to_string();
            let path = crate::collectors::startup::image_of(&image).unwrap_or_default();
            let signed = !path.is_empty() && shared.sigs.verify_now(&path).state == crate::model::SignatureState::Signed;
            let sev = if signed { Severity::Low } else { Severity::Medium };
            ev("service.installed", sev, format!("Yeni hizmet kuruldu: {}", d(r, "ServiceName")), format!("{image}{}", if signed { "" } else { " · imzasız" }));
        }
        (_, 1116 | 1117) => {
            ev(
                "defender.detection",
                Severity::High,
                format!("Defender zararlı yazılım buldu: {}", d(r, "Threat Name")),
                format!("{} · işlem: {}", d(r, "Path"), d(r, "Action Name")),
            );
        }
        (_, 5001) => ev("defense.change", Severity::High, "Defender gerçek zamanlı koruması kapatıldı".into(), String::new()),
        (_, 5007) if d(r, "New Value").contains("Exclusions") => {
            ev("defense.change", Severity::Medium, "Defender'a dışlama eklendi".into(), d(r, "New Value").to_string());
        }
        _ => {}
    }
}

fn brute_force(shared: &Shared) {
    let now = now_ms();
    let mut fails = FAILS.lock();
    while fails.front().is_some_and(|(t, _)| now - *t > FAIL_WINDOW_MS) {
        fails.pop_front();
    }
    let n = fails.len();
    let mut targets: Vec<&str> = fails.iter().map(|(_, w)| w.as_str()).collect();
    targets.sort();
    targets.dedup();
    let f = (n >= 5)
        .then(|| {
            let w = if n >= 20 { 60 } else { 40 };
            finding(
                "evt:bruteforce",
                "account",
                "Security",
                format!("Şifre deneme saldırısı: 10 dakikada {n} başarısız oturum açma"),
                vec![sig("evt.bruteforce", "Çok sayıda başarısız oturum açma denemesi", w, targets.into_iter().take(5).collect::<Vec<_>>().join(", "))],
                vec![],
            )
        })
        .flatten();
    drop(fails);
    set_findings(shared, "evt:bruteforce", f.into_iter().collect());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_fields() {
        let x = "<Event><System><EventID Qualifiers='0'>4625</EventID><EventRecordID>991</EventRecordID>\
                 <TimeCreated SystemTime='2026-11-16T20:00:00.000Z'/></System><EventData>\
                 <Data Name='TargetUserName'>refo</Data><Data Name='IpAddress'>10.0.0.9</Data>\
                 <Data Name='Empty'/><Data Name='Path'>C:\\a&amp;b</Data></EventData></Event>";
        let r = parse_xml(x);
        assert_eq!((r.id, r.record), (4625, 991));
        assert_eq!(r.time, "2026-11-16T20:00:00.000Z");
        assert_eq!(r.data["TargetUserName"], "refo");
        assert_eq!(r.data["Empty"], "");
        assert_eq!(r.data["Path"], "C:\\a&b");
    }

    #[test]
    fn xpath_shape() {
        assert_eq!(ids_xpath("1,2", 7), "*[System[(EventID=1 or EventID=2) and EventRecordID > 7]]");
    }

    #[test]
    fn live_system_channel_is_readable() {
        let r = query("System", "*", true, 1);
        assert!(r.is_ok(), "System log should be readable by standard users");
        eprintln!("{:?}", r.map(|v| v.first().map(|x| (x.id, x.record))));
        eprintln!("security: {:?}", query("Security", "*", true, 1).map(|v| v.len()));
    }
}
