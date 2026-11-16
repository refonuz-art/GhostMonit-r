//! One-click blocking through Windows Firewall rules (netsh advfirewall).
//!
//! Every rule we create is named "Ghost Monitor - …" and recorded in the database so it can
//! be listed and removed again. Adding or removing a rule needs administrator rights; when
//! we are not elevated, netsh is started through the UAC "runas" verb so Windows asks the
//! user for consent each time. Inputs are validated strictly: program paths must be existing
//! absolute .exe files and addresses must parse as IP addresses, so nothing user-supplied
//! can smuggle extra netsh arguments.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::now_ms;
use crate::state::Shared;
use crate::winapi::wide;

pub const PREFIX: &str = "Ghost Monitor - ";
const STORE_KEY: &str = "fw_rules";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BlockRule {
    pub name: String,
    /// "program" or "ip"
    pub kind: String,
    pub target: String,
    pub created: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Program(String),
    Ip(IpAddr),
}

pub fn validate(kind: &str, target: &str) -> Result<Target, String> {
    match kind {
        "program" => {
            let p = Path::new(target);
            let ok_chars = !target.chars().any(|c| matches!(c, '"' | '\r' | '\n' | '\0' | '%'));
            let is_exe = p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"));
            if !ok_chars || !p.is_absolute() || !is_exe || !p.is_file() {
                return Err("Geçerli bir program yolu değil (var olan bir .exe dosyası olmalı)".into());
            }
            let lower = target.to_ascii_lowercase();
            let own = std::env::current_exe().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
            if lower == own {
                return Err("Ghost Monitor kendini engelleyemez".into());
            }
            if lower.ends_with(r"\system32\svchost.exe") || lower.ends_with(r"\system32\lsass.exe") || lower.ends_with(r"\system32\services.exe") {
                return Err("Bu çekirdek Windows işlemini engellemek bağlantınızı tamamen kesebilir; izin verilmiyor".into());
            }
            Ok(Target::Program(target.to_string()))
        }
        "ip" => {
            let ip: IpAddr = target.trim().parse().map_err(|_| "Geçerli bir IP adresi değil".to_string())?;
            if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
                return Err("Bu adres engellenemez".into());
            }
            Ok(Target::Ip(ip))
        }
        _ => Err("Bilinmeyen kural türü".into()),
    }
}

fn safe_label(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ' | ':')).take(80).collect()
}

pub fn rule_name(t: &Target) -> String {
    match t {
        Target::Program(p) => format!("{PREFIX}{}", safe_label(&Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())),
        Target::Ip(ip) => format!("{PREFIX}{}", safe_label(&ip.to_string())),
    }
}

/// netsh argument lines (one per direction) that create the rule.
pub fn add_args(name: &str, t: &Target) -> Vec<String> {
    ["out", "in"]
        .iter()
        .map(|dir| match t {
            Target::Program(p) => format!(r#"advfirewall firewall add rule name="{name}" dir={dir} action=block program="{p}" enable=yes profile=any"#),
            Target::Ip(ip) => format!(r#"advfirewall firewall add rule name="{name}" dir={dir} action=block remoteip={ip} enable=yes profile=any"#),
        })
        .collect()
}

fn netsh_path() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\netsh.exe")
}

/// Run netsh with the given argument line, elevated through UAC if we are not admin.
/// Returns the exit code.
fn netsh(args: &str) -> Result<u32, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let file = wide(&netsh_path());
    let params = wide(args);
    let verb = wide(if crate::winapi::elevation::is_elevated() { "open" } else { "runas" });
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe {
        ShellExecuteExW(&mut info).map_err(|e| {
            if e.code().0 as u32 == 0x800704C7 {
                "Yönetici izni verilmedi".to_string()
            } else {
                format!("netsh başlatılamadı: {}", e.message())
            }
        })?;
        if info.hProcess.is_invalid() {
            return Err("netsh başlatılamadı".into());
        }
        WaitForSingleObject(info.hProcess, 20_000);
        let mut code = 1u32;
        let _ = GetExitCodeProcess(info.hProcess, &mut code);
        let _ = CloseHandle(info.hProcess);
        Ok(code)
    }
}

pub fn rules(shared: &Shared) -> Vec<BlockRule> {
    shared.store.lock().setting(STORE_KEY).ok().flatten().and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default()
}

fn save(shared: &Shared, list: &[BlockRule]) {
    let _ = shared.store.lock().set_setting(STORE_KEY, &serde_json::to_string(list).unwrap_or_default());
}

/// Without elevation each netsh call is its own UAC prompt, so only the outbound rule is
/// created (it is the one that stops data leaving the machine). When Ghost Monitor already
/// runs as administrator both directions are blocked. A netsh script file would allow one
/// prompt for both, but a user-writable file executed elevated is a privilege-escalation
/// hole, so we don't do that.
pub fn block(shared: &Shared, kind: &str, target: &str) -> Result<BlockRule, String> {
    let t = validate(kind, target)?;
    let name = rule_name(&t);
    if rules(shared).iter().any(|r| r.name == name) {
        return Err("Bu hedef için zaten bir engelleme kuralı var".into());
    }
    let lines = add_args(&name, &t);
    let elevated = crate::winapi::elevation::is_elevated();
    let todo: &[String] = if elevated { &lines } else { &lines[..1] };
    for l in todo {
        let code = netsh(l)?;
        if code != 0 {
            return Err(format!("Güvenlik duvarı kuralı eklenemedi (netsh çıkış kodu {code})"));
        }
    }
    let rule = BlockRule {
        name,
        kind: kind.into(),
        target: match &t {
            Target::Program(p) => p.clone(),
            Target::Ip(ip) => ip.to_string(),
        },
        created: now_ms(),
    };
    let mut list = rules(shared);
    list.push(rule.clone());
    save(shared, &list);
    Ok(rule)
}

pub fn unblock(shared: &Shared, name: &str) -> Result<(), String> {
    let mut list = rules(shared);
    // Only rules we created (looked up from our own list, never free text) can be removed.
    let Some(pos) = list.iter().position(|r| r.name == name) else {
        return Err("Bu kural Ghost Monitor tarafından oluşturulmamış".into());
    };
    let code = netsh(&format!(r#"advfirewall firewall delete rule name="{}""#, list[pos].name))?;
    // 1 = "No rules match" — already gone, which is fine to forget.
    if code != 0 && code != 1 {
        return Err(format!("Kural kaldırılamadı (netsh çıkış kodu {code})"));
    }
    list.remove(pos);
    save(shared, &list);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_injection() {
        assert!(validate("ip", "1.2.3.4 dir=in action=allow").is_err());
        assert!(validate("ip", "127.0.0.1").is_err());
        assert!(validate("ip", "0.0.0.0").is_err());
        assert_eq!(validate("ip", " 203.0.113.7 ").unwrap(), Target::Ip("203.0.113.7".parse().unwrap()));
        assert!(validate("program", r#"C:\x.exe" action=allow"#).is_err());
        assert!(validate("program", "relative.exe").is_err());
        assert!(validate("program", r"C:\Windows\System32\svchost.exe").is_err());
        let np = format!(r"{}\System32\notepad.exe", std::env::var("SystemRoot").unwrap());
        assert!(validate("program", &np).is_ok());
        assert!(validate("other", "x").is_err());
    }

    #[test]
    fn rule_lines() {
        let t = Target::Ip("203.0.113.7".parse().unwrap());
        let n = rule_name(&t);
        assert_eq!(n, "Ghost Monitor - 203.0.113.7");
        let a = add_args(&n, &t);
        assert!(a[0].contains("dir=out") && a[0].contains("remoteip=203.0.113.7"));
        assert!(a[1].contains("dir=in"));
    }
}
