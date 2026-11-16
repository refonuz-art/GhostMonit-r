//! Microsoft Defender, other registered antivirus products, Windows Firewall profiles and
//! the most recent Windows update, read with one hidden PowerShell call every 10 minutes.
//! Disabling protection or adding exclusions is usually malware's first move.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::AppHandle;

use super::{emit, finding, now_ms, powershell, set_findings};
use crate::engine::rules::sig;
use crate::model::{Severity, Signal};
use crate::monitor::{emit_event, event};
use crate::state::Shared;

const SCRIPT: &str = r#"
$o=@{}
try{$m=Get-MpComputerStatus -ErrorAction Stop
 $o.mp=@{am=[bool]$m.AMServiceEnabled; av=[bool]$m.AntivirusEnabled; rtp=[bool]$m.RealTimeProtectionEnabled; bm=[bool]$m.BehaviorMonitorEnabled; tamper=[bool]$m.IsTamperProtected; sigAge=[int]$m.AntivirusSignatureAge; quickAge=[int]$m.QuickScanAge; mode="$($m.AMRunningMode)"}}catch{$o.mpErr="$($_.Exception.Message)"}
try{$p=Get-MpPreference -ErrorAction Stop; $o.excl=@(@($p.ExclusionPath)+@($p.ExclusionExtension)+@($p.ExclusionProcess) | ?{$_} | %{"$_"})}catch{}
try{$o.av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | %{@{name="$($_.displayName)"; state=[int]$_.productState}})}catch{}
try{$o.fw=@(Get-NetFirewallProfile -ErrorAction Stop | %{@{name="$($_.Name)"; enabled=("$($_.Enabled)" -eq 'True')}})}catch{}
try{$h=Get-HotFix -ErrorAction Stop | ?{$_.InstalledOn} | sort InstalledOn -Descending | select -First 1; if($h){$o.hotfix=@{id="$($h.HotFixID)"; date=$h.InstalledOn.ToString('yyyy-MM-dd')}}}catch{}
$o | ConvertTo-Json -Depth 4 -Compress
"#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AvProduct {
    pub name: String,
    pub enabled: bool,
    pub up_to_date: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FirewallProfile {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStatus {
    pub checked: i64,
    /// None when Defender could not be queried (e.g. replaced by another antivirus).
    pub defender_available: bool,
    pub realtime: Option<bool>,
    pub behavior: Option<bool>,
    pub tamper: Option<bool>,
    pub signature_age_days: Option<i64>,
    pub quick_scan_age_days: Option<i64>,
    pub mode: Option<String>,
    /// None = only visible to administrators.
    pub exclusions: Option<Vec<String>>,
    pub products: Vec<AvProduct>,
    pub firewall: Vec<FirewallProfile>,
    pub last_update: Option<String>,
    pub last_update_id: Option<String>,
    pub signals: Vec<Signal>,
    pub error: Option<String>,
}

/// WSC productState: bits 12–15 = on/off, bits 4–7 = definitions out of date.
pub fn decode_state(s: i64) -> (bool, bool) {
    (((s >> 12) & 0xF) == 1, ((s >> 4) & 0xF) == 0)
}

fn b(v: &Value, k: &str) -> Option<bool> {
    v.get(k).and_then(Value::as_bool)
}
fn i(v: &Value, k: &str) -> Option<i64> {
    v.get(k).and_then(Value::as_i64).filter(|n| *n >= 0 && *n < 60000)
}

pub fn parse(json_text: &str) -> SecurityStatus {
    let v: Value = serde_json::from_str(json_text.trim()).unwrap_or(Value::Null);
    let mp = v.get("mp").cloned().unwrap_or(Value::Null);
    let as_list = |x: Option<&Value>| -> Vec<Value> {
        match x {
            Some(Value::Array(a)) => a.clone(),
            Some(o @ Value::Object(_)) => vec![o.clone()], // ConvertTo-Json unwraps single items
            _ => vec![],
        }
    };
    let products = as_list(v.get("av"))
        .iter()
        .map(|p| {
            let (enabled, up_to_date) = decode_state(p.get("state").and_then(Value::as_i64).unwrap_or(0));
            AvProduct { name: p.get("name").and_then(Value::as_str).unwrap_or("?").into(), enabled, up_to_date }
        })
        .collect();
    let firewall = as_list(v.get("fw"))
        .iter()
        .map(|p| FirewallProfile {
            name: match p.get("name").and_then(Value::as_str).unwrap_or("") {
                "Domain" => "Etki alanı".into(),
                "Private" => "Özel".into(),
                "Public" => "Ortak".into(),
                n => n.into(),
            },
            enabled: p.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        })
        .collect();
    let exclusions = match v.get("excl") {
        Some(Value::Array(a)) => {
            let list: Vec<String> = a.iter().filter_map(|x| x.as_str()).map(str::to_string).collect();
            // Standard users get a placeholder string instead of the list.
            if list.iter().any(|s| s.starts_with("N/A")) { None } else { Some(list) }
        }
        Some(Value::String(s)) if !s.starts_with("N/A") => Some(vec![s.clone()]),
        Some(Value::String(_)) => None,
        _ => Some(vec![]),
    };
    SecurityStatus {
        checked: now_ms(),
        defender_available: mp.is_object(),
        realtime: b(&mp, "rtp"),
        behavior: b(&mp, "bm"),
        tamper: b(&mp, "tamper"),
        signature_age_days: i(&mp, "sigAge"),
        quick_scan_age_days: i(&mp, "quickAge"),
        mode: mp.get("mode").and_then(Value::as_str).map(str::to_string),
        exclusions: if mp.is_object() { exclusions } else { None },
        products,
        firewall,
        last_update: v.pointer("/hotfix/date").and_then(Value::as_str).map(str::to_string),
        last_update_id: v.pointer("/hotfix/id").and_then(Value::as_str).map(str::to_string),
        signals: vec![],
        error: v.get("mpErr").and_then(Value::as_str).map(str::to_string),
    }
}

fn broad_exclusion(e: &str) -> bool {
    let l = e.to_ascii_lowercase().trim_end_matches('\\').to_string();
    l.len() <= 3 // "c:" / "c:\"
        || ["\\users", "\\appdata", "\\temp", "\\downloads", "\\windows", "\\programdata"].iter().any(|s| l.ends_with(s))
        || matches!(l.trim_start_matches('.'), "exe" | "dll" | "ps1" | "bat" | "js" | "vbs" | "scr")
        || ["powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe"].iter().any(|p| l.ends_with(p))
}

pub fn evaluate(s: &SecurityStatus, known_exclusions: Option<&[String]>) -> Vec<Signal> {
    let mut v = Vec::new();
    let other_av = s.products.iter().any(|p| p.enabled && !p.name.to_ascii_lowercase().contains("defender"));
    if s.realtime == Some(false) && !other_av {
        v.push(sig("def.rtp_off", "Gerçek zamanlı koruma kapalı ve başka antivirüs etkin değil", 60, "Microsoft Defender"));
    }
    if !s.products.is_empty() && !s.products.iter().any(|p| p.enabled) {
        v.push(sig("def.no_av", "Hiçbir antivirüs etkin değil", 60, s.products.iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ")));
    }
    if s.tamper == Some(false) && !other_av {
        v.push(sig("def.tamper_off", "Defender kurcalama koruması kapalı", 10, "Tamper Protection"));
    }
    if s.signature_age_days.is_some_and(|d| d > 7) && !other_av {
        v.push(sig("def.sig_old", "Virüs tanımları güncel değil", 15, format!("{} gün", s.signature_age_days.unwrap_or(0))));
    }
    if let Some(ex) = &s.exclusions {
        let broad: Vec<&String> = ex.iter().filter(|e| broad_exclusion(e)).collect();
        if !broad.is_empty() {
            v.push(sig("def.exclusion_broad", "Defender'a çok geniş bir dışlama eklenmiş", 50, broad.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
        }
        if let Some(known) = known_exclusions {
            let new: Vec<&String> = ex.iter().filter(|e| !known.contains(e)).collect();
            if !new.is_empty() {
                v.push(sig("def.exclusion_new", "Defender'a yeni dışlama eklendi", 35, new.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
            }
        }
    }
    let off: Vec<&str> = s.firewall.iter().filter(|p| !p.enabled).map(|p| p.name.as_str()).collect();
    if !off.is_empty() {
        v.push(sig("fw.off", "Windows Güvenlik Duvarı kapalı", 35, off.join(", ")));
    }
    v
}

pub fn tick(app: &AppHandle, shared: &Shared) {
    let mut s = match powershell(SCRIPT, Duration::from_secs(60)) {
        Ok(out) => parse(&out),
        Err(e) => SecurityStatus { checked: now_ms(), error: Some(e), ..Default::default() },
    };
    let st = shared.store.lock();
    let known: Option<Vec<String>> = st.setting("defender_exclusions").ok().flatten().and_then(|v| serde_json::from_str(&v).ok());
    if let Some(ex) = &s.exclusions {
        let _ = st.set_setting("defender_exclusions", &serde_json::to_string(ex).unwrap_or_default());
    }
    drop(st);
    s.signals = evaluate(&s, known.as_deref());

    // Transitions worth an event (protection switched off).
    let prev = shared.guard.read().defender.clone();
    if let Some(p) = prev {
        if p.realtime == Some(true) && s.realtime == Some(false) {
            emit_event(app, shared, event("defense.change", Severity::High, "Defender gerçek zamanlı koruması kapatıldı".into(), String::new(), None, json!({})));
        }
        for f in &s.firewall {
            if !f.enabled && p.firewall.iter().any(|q| q.name == f.name && q.enabled) {
                emit_event(app, shared, event("defense.change", Severity::High, format!("Güvenlik duvarı kapatıldı: {} profil", f.name), String::new(), None, json!({})));
            }
        }
    }
    let f = finding("defense:system", "defense", "Windows Güvenliği", "Koruma ayarları zayıflatılmış".into(), s.signals.clone(), vec![]);
    set_findings(shared, "defense:", f.into_iter().filter(|f| f.severity >= Severity::Medium).collect());
    shared.guard.write().defender = Some(s);
    emit(app, shared);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_state_decoding() {
        assert_eq!(decode_state(0x061100), (true, true)); // Defender on, up to date
        assert_eq!(decode_state(0x060100), (false, true)); // off
        assert_eq!(decode_state(0x061110), (true, false)); // on, outdated
    }

    #[test]
    fn parse_and_evaluate() {
        let j = r#"{"mp":{"am":true,"av":true,"rtp":false,"bm":true,"tamper":true,"sigAge":0,"quickAge":3,"mode":"Normal"},
            "excl":["C:\\","C:\\Projects"],"av":{"name":"Windows Defender","state":397568},
            "fw":[{"name":"Domain","enabled":true},{"name":"Public","enabled":false}],"hotfix":{"id":"KB1","date":"2026-11-01"}}"#;
        let s = parse(j);
        assert_eq!(s.realtime, Some(false));
        assert_eq!(s.products.len(), 1);
        assert_eq!(s.exclusions.as_ref().unwrap().len(), 2);
        let sig = evaluate(&s, Some(&["C:\\".to_string()]));
        let rules: Vec<&str> = sig.iter().map(|s| s.rule.as_str()).collect();
        assert!(rules.contains(&"def.rtp_off"), "{rules:?}");
        assert!(rules.contains(&"def.exclusion_broad"));
        assert!(rules.contains(&"def.exclusion_new"));
        assert!(rules.contains(&"fw.off"));
        // Non-admin placeholder → unknown, not "no exclusions".
        let s = parse(r#"{"mp":{"rtp":true},"excl":["N/A: Must be an administrator to view exclusions"]}"#);
        assert_eq!(s.exclusions, None);
    }

    #[test]
    fn other_av_silences_defender_off() {
        let s = SecurityStatus {
            realtime: Some(false),
            products: vec![AvProduct { name: "ESET Security".into(), enabled: true, up_to_date: true }],
            ..Default::default()
        };
        assert!(evaluate(&s, None).is_empty());
    }

    #[test]
    #[ignore = "spawns PowerShell; run manually"]
    fn live() {
        let out = powershell(SCRIPT, Duration::from_secs(60)).unwrap();
        eprintln!("{out}");
        eprintln!("{:#?}", parse(&out));
    }
}
