//! Security health score: a checklist built from what the other guards measured plus a few
//! registry settings. Every check that could not be measured is shown as "bilinmiyor" and
//! does not change the score — nothing is assumed.

use serde::Serialize;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

use super::now_ms;
use crate::model::{Severity, SignatureState};
use crate::state::Shared;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Bad,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub id: String,
    pub label: String,
    pub status: Status,
    pub detail: String,
    /// Points lost when the check fails (half for a warning).
    pub weight: u32,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthReport {
    pub score: u32,
    pub grade: String,
    pub computed: i64,
    pub checks: Vec<Check>,
}

fn check(id: &str, label: &str, status: Status, detail: impl Into<String>, weight: u32, fix: Option<&str>) -> Check {
    Check { id: id.into(), label: label.into(), status, detail: detail.into(), weight, fix: fix.map(str::to_string) }
}

fn reg_u32(path: &str, name: &str) -> Option<u32> {
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(path, KEY_READ).ok()?.get_value(name).ok()
}

pub fn score(checks: &[Check]) -> u32 {
    let lost: u32 = checks
        .iter()
        .map(|c| match c.status {
            Status::Bad => c.weight,
            Status::Warn => c.weight / 2,
            _ => 0,
        })
        .sum();
    100u32.saturating_sub(lost)
}

pub fn grade(score: u32) -> &'static str {
    match score {
        90..=100 => "İyi",
        70..=89 => "Orta",
        50..=69 => "Zayıf",
        _ => "Kötü",
    }
}

pub fn build(shared: &Shared) -> HealthReport {
    let g = shared.guard.read().clone();
    let mut v = Vec::new();

    // ---- antivirus / Defender ----
    match &g.defender {
        Some(d) if d.defender_available || !d.products.is_empty() => {
            let any_av = d.products.iter().any(|p| p.enabled) || d.realtime == Some(true);
            v.push(check(
                "av",
                "Antivirüs koruması",
                if any_av { Status::Ok } else { Status::Bad },
                if d.products.is_empty() {
                    format!("Defender gerçek zamanlı koruma: {}", if d.realtime == Some(true) { "açık" } else { "kapalı" })
                } else {
                    d.products.iter().map(|p| format!("{} ({})", p.name, if p.enabled { "açık" } else { "kapalı" })).collect::<Vec<_>>().join(", ")
                },
                30,
                Some("Windows Güvenliği → Virüs ve tehdit koruması → Gerçek zamanlı korumayı açın"),
            ));
            if let Some(age) = d.signature_age_days {
                v.push(check(
                    "sig",
                    "Virüs tanımları güncel",
                    if age <= 3 { Status::Ok } else if age <= 7 { Status::Warn } else { Status::Bad },
                    format!("{age} gün önce güncellendi"),
                    10,
                    Some("Windows Güvenliği → Koruma güncelleştirmeleri → Güncelleştirmeleri denetle"),
                ));
            }
            if let Some(t) = d.tamper {
                v.push(check("tamper", "Kurcalama koruması", if t { Status::Ok } else { Status::Warn }, if t { "açık" } else { "kapalı" }, 6, Some("Windows Güvenliği → Virüs ve tehdit koruması ayarları → Kurcalama koruması")));
            }
            match &d.exclusions {
                Some(ex) => {
                    let broad = d.signals.iter().any(|s| s.rule == "def.exclusion_broad");
                    v.push(check(
                        "excl",
                        "Defender dışlamaları",
                        if broad { Status::Bad } else if ex.is_empty() { Status::Ok } else { Status::Warn },
                        if ex.is_empty() { "dışlama yok".to_string() } else { format!("{} dışlama: {}", ex.len(), ex.iter().take(3).cloned().collect::<Vec<_>>().join(", ")) },
                        10,
                        Some("Tanımadığınız dışlamaları Windows Güvenliği → Dışlamalar bölümünden kaldırın"),
                    ));
                }
                None => v.push(check("excl", "Defender dışlamaları", Status::Unknown, "listeyi yalnızca yönetici görebilir", 10, None)),
            }
            if !d.firewall.is_empty() {
                let off: Vec<&str> = d.firewall.iter().filter(|p| !p.enabled).map(|p| p.name.as_str()).collect();
                v.push(check(
                    "fw",
                    "Güvenlik duvarı",
                    if off.is_empty() { Status::Ok } else { Status::Bad },
                    if off.is_empty() { "tüm profillerde açık".to_string() } else { format!("kapalı: {}", off.join(", ")) },
                    15,
                    Some("Windows Güvenliği → Güvenlik duvarı ve ağ koruması → profilleri açın"),
                ));
            } else {
                v.push(check("fw", "Güvenlik duvarı", Status::Unknown, "durum okunamadı", 15, None));
            }
            match &d.last_update {
                Some(date) => {
                    let days = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
                        .ok()
                        .map(|d| (chrono::Local::now().date_naive() - d).num_days());
                    let st = match days {
                        Some(n) if n <= 45 => Status::Ok,
                        Some(n) if n <= 90 => Status::Warn,
                        Some(_) => Status::Bad,
                        None => Status::Unknown,
                    };
                    v.push(check("wu", "Windows güncellemeleri", st, format!("son güncelleme {date}{}", days.map(|n| format!(" ({n} gün önce)")).unwrap_or_default()), 10, Some("Ayarlar → Windows Update → Güncelleştirmeleri denetle")));
                }
                None => v.push(check("wu", "Windows güncellemeleri", Status::Unknown, "son güncelleme tarihi okunamadı", 10, None)),
            }
        }
        Some(d) => v.push(check("av", "Antivirüs koruması", Status::Unknown, d.error.clone().unwrap_or_else(|| "Windows Güvenliği sorgulanamadı".into()), 30, None)),
        None => v.push(check("av", "Antivirüs koruması", Status::Unknown, "ilk kontrol henüz tamamlanmadı", 30, None)),
    }

    // ---- registry settings ----
    match reg_u32(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA") {
        Some(1) | None => v.push(check("uac", "Kullanıcı Hesabı Denetimi (UAC)", Status::Ok, "açık", 10, None)),
        Some(_) => v.push(check("uac", "Kullanıcı Hesabı Denetimi (UAC)", Status::Bad, "kapalı — programlar sormadan yönetici olabilir", 10, Some("Denetim Masası → Kullanıcı Hesapları → Kullanıcı Hesabı Denetimi ayarlarını değiştir"))),
    }
    // SMBv1 client driver installed and not disabled.
    match reg_u32(r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start") {
        None | Some(4) => v.push(check("smb1", "Eski SMBv1 protokolü", Status::Ok, "kapalı / yüklü değil", 8, None)),
        Some(_) => v.push(check("smb1", "Eski SMBv1 protokolü", Status::Bad, "açık — WannaCry gibi solucanların kullandığı eski protokol", 8, Some("Windows özelliklerini aç veya kapat → SMB 1.0/CIFS desteğini kaldırın"))),
    }
    match reg_u32(r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") {
        Some(0) => {
            let nla = reg_u32(r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication") == Some(1);
            v.push(check(
                "rdp",
                "Uzak Masaüstü",
                if nla { Status::Warn } else { Status::Bad },
                if nla { "açık (ağ düzeyinde kimlik doğrulama ile)" } else { "açık ve ağ düzeyinde kimlik doğrulama kapalı" },
                8,
                Some("Kullanmıyorsanız Ayarlar → Sistem → Uzak Masaüstü'nü kapatın"),
            ));
        }
        _ => v.push(check("rdp", "Uzak Masaüstü", Status::Ok, "kapalı", 8, None)),
    }

    // ---- what Ghost Monitor itself sees ----
    let unsigned = shared
        .processes
        .read()
        .iter()
        .filter(|p| matches!(p.signature.state, SignatureState::Unsigned | SignatureState::Invalid) && p.exe.is_some())
        .count();
    v.push(check(
        "unsigned",
        "İmzasız çalışan programlar",
        match unsigned {
            0..=3 => Status::Ok,
            4..=10 => Status::Warn,
            _ => Status::Bad,
        },
        format!("{unsigned} imzasız veya geçersiz imzalı işlem"),
        6,
        Some("Süreçler ekranında imzasız programları inceleyin"),
    ));
    let open_high = shared.findings.read().iter().filter(|f| f.severity >= Severity::High).count();
    v.push(check(
        "findings",
        "Açık yüksek riskli bulgu",
        if open_high == 0 { Status::Ok } else { Status::Bad },
        format!("{open_high} adet"),
        15,
        Some("Tehdit ekranından bulguları inceleyin"),
    ));
    if let Some(n) = &g.netconf {
        let bad = n.signals.iter().any(|s| s.weight >= 25);
        v.push(check(
            "netconf",
            "hosts / DNS / proxy",
            if bad { Status::Bad } else if n.signals.is_empty() { Status::Ok } else { Status::Warn },
            if n.signals.is_empty() { "yönlendirme yok".to_string() } else { n.signals.iter().map(|s| s.label.clone()).collect::<Vec<_>>().join(" · ") },
            10,
            None,
        ));
    }
    let risky_ext = g.extensions.iter().filter(|e| e.enabled && e.severity >= Severity::High).count();
    if g.extensions_scanned.is_some() {
        v.push(check(
            "ext",
            "Tarayıcı uzantıları",
            if risky_ext == 0 { Status::Ok } else { Status::Warn },
            format!("{} uzantı, {risky_ext} tanesi yüksek riskli izinlere sahip", g.extensions.len()),
            8,
            Some("Sağlık ekranındaki uzantı listesinden tanımadıklarınızı kaldırın"),
        ));
    }
    v.push(check(
        "ransom",
        "Fidye yazılımı kalkanı",
        if g.canary.enabled { Status::Ok } else { Status::Warn },
        if g.canary.enabled { format!("{} tuzak dosya, {} klasör izleniyor", g.canary.files.len(), g.canary.watched_folders.len()) } else { "kapalı".to_string() },
        6,
        Some("Ayarlar → Fidye yazılımı kalkanını açın"),
    ));

    let s = score(&v);
    HealthReport { score: s, grade: grade(s).into(), computed: now_ms(), checks: v }
}

pub fn refresh(shared: &Shared) {
    let r = build(shared);
    // Keep one score per day (latest wins) for the weekly comparison.
    if r.checks.iter().any(|c| c.status != Status::Unknown) {
        let day = chrono::Local::now().format("%Y-%m-%d").to_string();
        let checks: Vec<(&str, &Status)> = r.checks.iter().map(|c| (c.label.as_str(), &c.status)).collect();
        let _ = shared.store.lock().conn.execute(
            "INSERT OR REPLACE INTO health_history (day, score, checks, ts) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![day, r.score, serde_json::to_string(&checks).unwrap_or_default(), r.computed],
        );
    }
    shared.guard.write().health = Some(r);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoring() {
        let c = vec![
            check("a", "a", Status::Bad, "", 30, None),
            check("b", "b", Status::Warn, "", 10, None),
            check("c", "c", Status::Unknown, "", 50, None),
            check("d", "d", Status::Ok, "", 50, None),
        ];
        assert_eq!(score(&c), 65);
        assert_eq!(grade(65), "Zayıf");
        assert_eq!(grade(100), "İyi");
    }
}
