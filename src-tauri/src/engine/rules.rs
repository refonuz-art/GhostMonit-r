//! Individual detection rules. Each rule yields weighted `Signal`s; no rule decides
//! "malicious" on its own — scoring in `engine::score` combines them.

use crate::model::{AddrScope, ConnectionInfo, ProcessInfo, Signal, SignatureState};

pub fn sig(rule: &str, label: &str, weight: u32, evidence: impl Into<String>) -> Signal {
    Signal { rule: rule.into(), label: label.into(), weight, evidence: evidence.into() }
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase().replace('/', "\\")
}

fn system_root() -> String {
    lower(&std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()))
}

/// System binaries and the directories they legitimately live in (relative to %SystemRoot%).
const SYSTEM_BINARIES: &[(&str, &[&str])] = &[
    ("svchost.exe", &["\\system32\\", "\\syswow64\\"]),
    ("lsass.exe", &["\\system32\\"]),
    ("csrss.exe", &["\\system32\\"]),
    ("smss.exe", &["\\system32\\"]),
    ("wininit.exe", &["\\system32\\"]),
    ("winlogon.exe", &["\\system32\\"]),
    ("services.exe", &["\\system32\\"]),
    ("spoolsv.exe", &["\\system32\\"]),
    ("taskhostw.exe", &["\\system32\\"]),
    ("dllhost.exe", &["\\system32\\", "\\syswow64\\"]),
    ("rundll32.exe", &["\\system32\\", "\\syswow64\\"]),
    ("conhost.exe", &["\\system32\\"]),
    ("dwm.exe", &["\\system32\\"]),
    ("ctfmon.exe", &["\\system32\\", "\\syswow64\\"]),
    ("sihost.exe", &["\\system32\\"]),
    ("explorer.exe", &["\\", "\\syswow64\\"]),
    ("lsm.exe", &["\\system32\\"]),
    ("wmiprvse.exe", &["\\system32\\wbem\\", "\\syswow64\\wbem\\"]),
];

fn edit_distance_le1(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (la, lb) = (a.len(), b.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    let (mut i, mut j, mut diff) = (0, 0, 0);
    while i < la && j < lb {
        if a[i] == b[j] {
            i += 1;
            j += 1;
            continue;
        }
        diff += 1;
        if diff > 1 {
            return false;
        }
        match la.cmp(&lb) {
            std::cmp::Ordering::Greater => i += 1,
            std::cmp::Ordering::Less => j += 1,
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    diff + (la - i) + (lb - j) <= 1
}

/// Name of a system binary used from the wrong place, or a near-miss spelling of one.
pub fn masquerade(p: &ProcessInfo) -> Vec<Signal> {
    let name = p.name.to_ascii_lowercase();
    let mut out = Vec::new();
    let root = system_root();
    for (bin, dirs) in SYSTEM_BINARIES {
        if name == *bin {
            if let Some(exe) = &p.exe {
                let e = lower(exe);
                let ok = dirs.iter().any(|d| e == format!("{root}{d}{bin}"))
                    || e.starts_with(&format!("{root}\\winsxs\\"));
                if !ok {
                    out.push(sig(
                        "masquerade.path",
                        "Sistem dosyası adı beklenmeyen konumda",
                        50,
                        format!("{} → {}", p.name, exe),
                    ));
                }
            }
        } else if edit_distance_le1(&name, bin)
            && name.len() > 6
            && p.signature.state != SignatureState::Signed
        {
            out.push(sig(
                "masquerade.typo",
                "Sistem işlemine benzeyen ad",
                35,
                format!("'{}' ≈ '{}'", p.name, bin),
            ));
        }
    }
    out
}

/// Unsigned / invalid binaries, weighted by how unusual their location is.
pub fn signature_and_location(p: &ProcessInfo) -> Vec<Signal> {
    let Some(exe) = &p.exe else { return vec![] };
    let e = lower(exe);
    let mut out = Vec::new();
    match p.signature.state {
        SignatureState::Invalid => out.push(sig(
            "sig.invalid",
            "Geçersiz veya güvenilmeyen dijital imza",
            35,
            p.signature.publisher.clone().unwrap_or_else(|| exe.clone()),
        )),
        SignatureState::Unsigned => {
            let temp = e.contains("\\appdata\\local\\temp\\") || e.contains("\\windows\\temp\\");
            let user_rw = e.contains("\\appdata\\")
                || e.contains("\\downloads\\")
                || e.contains("\\users\\public\\")
                || e.contains("\\programdata\\")
                || e.contains("\\$recycle.bin\\");
            if temp {
                out.push(sig("loc.temp", "İmzasız dosya geçici klasörden çalışıyor", 30, exe.clone()));
            } else if user_rw {
                out.push(sig("loc.userwritable", "İmzasız dosya kullanıcı yazılabilir dizinden çalışıyor", 15, exe.clone()));
            } else {
                out.push(sig("sig.unsigned", "Dijital imza yok", 5, exe.clone()));
            }
        }
        _ => {}
    }
    out
}

const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
];
const DOC_APPS: &[&str] = &[
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe",
    "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "hwp.exe",
];

pub fn parent_child(p: &ProcessInfo, parent_name: Option<&str>) -> Vec<Signal> {
    let name = p.name.to_ascii_lowercase();
    let Some(parent) = parent_name.map(|s| s.to_ascii_lowercase()) else { return vec![] };
    if DOC_APPS.contains(&parent.as_str()) && SCRIPT_HOSTS.contains(&name.as_str()) {
        return vec![sig(
            "lineage.docspawn",
            "Ofis/PDF uygulaması betik yorumlayıcısı başlattı",
            45,
            format!("{parent} → {}", p.name),
        )];
    }
    vec![]
}

/// Obfuscation / download-cradle markers in PowerShell & script host command lines.
pub fn command_line(p: &ProcessInfo) -> Vec<Signal> {
    let name = p.name.to_ascii_lowercase();
    let Some(cmd) = &p.cmd else { return vec![] };
    let c = cmd.to_ascii_lowercase();
    let mut out = Vec::new();
    if name == "powershell.exe" || name == "pwsh.exe" {
        let markers: &[(&str, &str, u32)] = &[
            (" -enc", "Kodlanmış (Base64) PowerShell komutu", 25),
            (" -encodedcommand", "Kodlanmış (Base64) PowerShell komutu", 25),
            ("-w hidden", "Gizli pencerede PowerShell", 15),
            ("-windowstyle hidden", "Gizli pencerede PowerShell", 15),
            ("downloadstring", "PowerShell ile uzaktan betik indirme", 25),
            ("downloadfile", "PowerShell ile uzaktan dosya indirme", 20),
            ("net.webclient", "PowerShell WebClient kullanımı", 15),
            ("iex", "Invoke-Expression (dinamik kod çalıştırma)", 15),
            ("invoke-expression", "Invoke-Expression (dinamik kod çalıştırma)", 15),
            ("frombase64string", "Base64 çözme ile kod yükleme", 15),
            ("-executionpolicy bypass", "Çalıştırma ilkesi atlatma", 10),
            ("-ep bypass", "Çalıştırma ilkesi atlatma", 10),
            ("-nop", "Profil yüklemeden çalıştırma", 5),
            ("reflection.assembly", "Bellekten .NET derlemesi yükleme", 25),
            ("amsiutils", "AMSI atlatma girişimi", 40),
        ];
        let mut seen = std::collections::HashSet::new();
        for (m, label, w) in markers {
            let hit = if *m == "iex" {
                c.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-').any(|t| t == "iex")
            } else {
                c.contains(m)
            };
            if hit && seen.insert(*label) {
                out.push(sig("ps.cmdline", label, *w, cmd.chars().take(240).collect::<String>()));
            }
        }
    } else if ["mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"].contains(&name.as_str())
        && (c.contains("http://") || c.contains("https://") || c.contains("javascript:") || c.contains("scrobj"))
    {
        out.push(sig(
            "lolbin.remote",
            "Sistem aracı uzak içerikle çalıştırılıyor",
            35,
            cmd.chars().take(240).collect::<String>(),
        ));
    }
    out
}

const SUSPICIOUS_PORTS: &[u16] = &[4444, 4445, 1337, 31337, 6666, 6667, 6697, 12345, 5552, 3460, 9999, 1604];

pub fn network(p: &ProcessInfo, conns: &[&ConnectionInfo]) -> Vec<Signal> {
    let mut out = Vec::new();
    let public: Vec<&&ConnectionInfo> = conns
        .iter()
        .filter(|c| c.scope == AddrScope::Public && c.remote_addr.is_some() && c.state == "ESTABLISHED")
        .collect();
    let unsigned = matches!(p.signature.state, SignatureState::Unsigned | SignatureState::Invalid);
    if unsigned && !public.is_empty() {
        out.push(sig(
            "net.unsigned_public",
            "İmzasız işlem internete bağlanıyor",
            15,
            format!("{} uzak bağlantı", public.len()),
        ));
    }
    for c in &public {
        if let Some(port) = c.remote_port {
            if SUSPICIOUS_PORTS.contains(&port) {
                out.push(sig(
                    "net.badport",
                    "Bilinen arka kapı/C2 portuna bağlantı",
                    25,
                    format!("{}:{}", c.remote_addr.as_deref().unwrap_or("?"), port),
                ));
                break;
            }
        }
    }
    out
}

pub fn listening(p: &ProcessInfo, new_ports: &[String]) -> Vec<Signal> {
    if new_ports.is_empty() {
        return vec![];
    }
    let unsigned = matches!(p.signature.state, SignatureState::Unsigned | SignatureState::Invalid);
    vec![sig(
        "port.new",
        if unsigned { "İmzasız işlem yeni dış port açtı" } else { "Beklenmeyen yeni dinleme portu" },
        if unsigned { 25 } else { 10 },
        new_ports.join(", "),
    )]
}

pub fn resource(p: &ProcessInfo, high_cpu_secs: i64) -> Vec<Signal> {
    if high_cpu_secs < 120 {
        return vec![];
    }
    let unsigned = matches!(p.signature.state, SignatureState::Unsigned | SignatureState::Invalid);
    vec![sig(
        "res.cpu",
        "Uzun süreli yüksek CPU kullanımı",
        if unsigned { 15 } else { 5 },
        format!("{} sn boyunca %{:.0} üzeri", high_cpu_secs, p.cpu),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SignatureInfo;

    pub fn proc(name: &str, exe: &str, state: SignatureState, cmd: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: None,
            name: name.into(),
            exe: Some(exe.into()),
            cmd: cmd.map(Into::into),
            cpu: 0.0,
            memory: 0,
            start_time: 0,
            user: None,
            signature: SignatureInfo { state, publisher: None },
            connections: 0,
            critical: false,
            risk: None,
        }
    }

    #[test]
    fn typo_distance() {
        assert!(edit_distance_le1("svch0st.exe", "svchost.exe"));
        assert!(edit_distance_le1("scvhost.exe", "svchost.exe") == false);
        assert!(edit_distance_le1("lsas.exe", "lsass.exe"));
        assert!(!edit_distance_le1("svchost.exe", "svchost.exe"));
    }

    #[test]
    fn svchost_in_wrong_dir_is_flagged() {
        std::env::set_var("SystemRoot", "C:\\Windows");
        let ok = proc("svchost.exe", "C:\\Windows\\System32\\svchost.exe", SignatureState::Signed, None);
        assert!(masquerade(&ok).is_empty());
        let bad = proc("svchost.exe", "C:\\Users\\a\\AppData\\svchost.exe", SignatureState::Unsigned, None);
        assert_eq!(masquerade(&bad)[0].rule, "masquerade.path");
    }

    #[test]
    fn encoded_powershell() {
        let p = proc(
            "powershell.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            SignatureState::Signed,
            Some("powershell.exe -NoP -W Hidden -Enc SQBFAFgA"),
        );
        let s = command_line(&p);
        assert!(s.iter().any(|x| x.label.contains("Kodlanmış")));
        assert!(s.iter().any(|x| x.label.contains("Gizli")));
    }

    #[test]
    fn temp_unsigned_weighs_more() {
        let t = proc("a.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\a.exe", SignatureState::Unsigned, None);
        let a = proc("a.exe", "C:\\Users\\u\\AppData\\Roaming\\a.exe", SignatureState::Unsigned, None);
        assert!(signature_and_location(&t)[0].weight > signature_and_location(&a)[0].weight);
        let s = proc("a.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\a.exe", SignatureState::Signed, None);
        assert!(signature_and_location(&s).is_empty());
    }
}
