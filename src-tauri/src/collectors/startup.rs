//! Autostart inventory: Run keys, Winlogon, Startup folders, services, scheduled tasks.

use serde::Serialize;
use windows::core::{Interface, BSTR, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
    ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL,
    SERVICE_WIN32,
};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ITaskFolder, ITaskService, TaskScheduler, TASK_ACTION_EXEC, TASK_ENUM_HIDDEN,
};
use windows::Win32::System::Variant::VARIANT;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::RegKey;

use crate::model::{Severity, SignatureInfo};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupItem {
    /// Stable identity: kind|location|name
    pub id: String,
    pub kind: String,
    pub name: String,
    pub command: String,
    pub location: String,
    pub image: Option<String>,
    pub image_exists: bool,
    pub enabled: bool,
    /// services: start type; tasks: trigger summary is not collected
    pub start: Option<String>,
    pub state: Option<String>,
    pub account: Option<String>,
    pub author: Option<String>,
    pub signature: Option<SignatureInfo>,
    pub first_seen: i64,
    pub risk: Option<Severity>,
}

fn item(kind: &str, location: &str, name: &str, command: &str) -> StartupItem {
    let image = image_of(command);
    StartupItem {
        id: format!("{kind}|{}|{}", location.to_ascii_lowercase(), name.to_ascii_lowercase()),
        kind: kind.into(),
        name: name.into(),
        command: command.into(),
        location: location.into(),
        image_exists: image.as_deref().map(|p| std::path::Path::new(p).exists()).unwrap_or(false),
        image,
        enabled: true,
        start: None,
        state: None,
        account: None,
        author: None,
        signature: None,
        first_seen: 0,
        risk: None,
    }
}

pub fn expand_env(s: &str) -> String {
    let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buf = vec![0u16; 2048];
    let n = unsafe { ExpandEnvironmentStringsW(PCWSTR(w.as_ptr()), Some(&mut buf)) } as usize;
    if n == 0 || n > buf.len() {
        return s.to_string();
    }
    String::from_utf16_lossy(&buf[..n.saturating_sub(1)])
}

/// Extract the executable path from a command line as Windows would launch it.
pub fn image_of(command: &str) -> Option<String> {
    let c = expand_env(command.trim());
    if c.is_empty() {
        return None;
    }
    let raw = if let Some(rest) = c.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest).to_string()
    } else {
        let lower = c.to_ascii_lowercase();
        let mut cut = None;
        for ext in [".exe", ".com", ".bat", ".cmd", ".scr", ".dll", ".ps1", ".vbs", ".js", ".lnk", ".sys"] {
            if let Some(i) = lower.find(ext) {
                let end = i + ext.len();
                if lower[end..].is_empty() || lower[end..].starts_with(' ') || lower[end..].starts_with(',') {
                    cut = Some(cut.map_or(end, |c: usize| c.min(end)));
                }
            }
        }
        match cut {
            Some(e) => c[..e].to_string(),
            None => c.split_whitespace().next().unwrap_or("").to_string(),
        }
    };
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let mut p = raw.trim().to_string();
    if let Some(r) = p.strip_prefix(r"\SystemRoot\") {
        p = format!("{root}\\{r}");
    } else if let Some(r) = p.strip_prefix(r"\??\") {
        p = r.to_string();
    } else if p.to_ascii_lowercase().starts_with("system32\\") {
        p = format!("{root}\\{p}");
    }
    if !p.contains('\\') {
        // Bare name: resolve via System32 like the loader would for common hosts.
        let cand = format!("{root}\\System32\\{p}");
        if std::path::Path::new(&cand).exists() {
            p = cand;
        } else if std::path::Path::new(&format!("{cand}.exe")).exists() {
            p = format!("{cand}.exe");
        }
    }
    (!p.is_empty()).then_some(p)
}

// ---------------- registry ----------------

fn approved(root: &RegKey, sub: &str, name: &str) -> bool {
    root.open_subkey(format!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{sub}"))
        .and_then(|k| k.get_raw_value(name))
        .map(|v| v.bytes.first().map(|b| b & 1 == 0).unwrap_or(true))
        .unwrap_or(true)
}

fn registry_items(out: &mut Vec<StartupItem>) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let keys: [(&RegKey, &str, &str, &str, Option<&str>); 6] = [
        (&hkcu, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "Run", Some("Run")),
        (&hkcu, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce", None),
        (&hklm, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "Run", Some("Run")),
        (&hklm, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce", None),
        (&hklm, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run (32-bit)", Some("Run32")),
        (&hklm, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce (32-bit)", None),
    ];
    for (root, hive, path, _label, appr) in keys {
        let Ok(k) = root.open_subkey(path) else { continue };
        for (name, _) in k.enum_values().flatten() {
            let Ok(cmd) = k.get_value::<String, _>(&name) else { continue };
            let mut it = item("registry", &format!("{hive}\\{path}"), &name, &cmd);
            if let Some(a) = appr {
                it.enabled = approved(root, a, &name);
            }
            out.push(it);
        }
    }
    // Winlogon hijack points: only reported when they deviate from Windows defaults.
    if let Ok(k) = hklm.open_subkey(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()).to_ascii_lowercase();
        for (name, ok) in [
            ("Shell", vec!["explorer.exe".to_string()]),
            ("Userinit", vec![format!("{root}\\system32\\userinit.exe,"), format!("{root}\\system32\\userinit.exe")]),
        ] {
            if let Ok(v) = k.get_value::<String, _>(name) {
                if !ok.contains(&v.trim().to_ascii_lowercase()) {
                    out.push(item("winlogon", r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", name, &v));
                }
            }
        }
    }
}

// ---------------- startup folders ----------------

fn folder_items(out: &mut Vec<StartupItem>) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let dirs = [
        (std::env::var("APPDATA").ok().map(|a| format!(r"{a}\Microsoft\Windows\Start Menu\Programs\Startup")), &hkcu),
        (std::env::var("ProgramData").ok().map(|a| format!(r"{a}\Microsoft\Windows\Start Menu\Programs\StartUp")), &hklm),
    ];
    for (dir, root) in dirs {
        let Some(dir) = dir else { continue };
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let path = e.path().to_string_lossy().into_owned();
            // A shortcut is never signed itself; judge the program it launches.
            let command = if name.to_ascii_lowercase().ends_with(".lnk") {
                resolve_lnk(&path)
                    .map(|(t, a)| if a.is_empty() { format!("\"{t}\"") } else { format!("\"{t}\" {a}") })
                    .unwrap_or_else(|| format!("\"{path}\""))
            } else {
                format!("\"{path}\"")
            };
            let mut it = item("folder", &dir, &name, &command);
            it.enabled = approved(root, "StartupFolder", &name);
            out.push(it);
        }
    }
}

/// Target path and arguments of a .lnk shortcut.
pub fn resolve_lnk(path: &str) -> Option<(String, String)> {
    use windows::Win32::System::Com::{IPersistFile, STGM_READ};
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    unsafe {
        let init = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
        let r = (|| -> windows::core::Result<(String, String)> {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            let pf: IPersistFile = link.cast()?;
            let w = crate::winapi::wide(path);
            pf.Load(PCWSTR(w.as_ptr()), STGM_READ)?;
            let mut target = [0u16; 1024];
            link.GetPath(&mut target, std::ptr::null_mut(), 0)?;
            let mut args = [0u16; 2048];
            let _ = link.GetArguments(&mut args);
            let s = |b: &[u16]| String::from_utf16_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())]);
            Ok((s(&target), s(&args)))
        })();
        if init {
            CoUninitialize();
        }
        r.ok().filter(|(t, _)| !t.is_empty())
    }
}

// ---------------- services ----------------

fn wstr(p: windows::core::PWSTR) -> Option<String> {
    if p.is_null() {
        None
    } else {
        unsafe { p.to_string().ok() }.filter(|s| !s.is_empty())
    }
}

fn service_items(out: &mut Vec<StartupItem>) {
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)
        else {
            return;
        };
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut count,
            Some(&mut resume),
            PCWSTR::null(),
        );
        let mut buf = vec![0u8; needed as usize + 4096];
        resume = 0;
        if EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buf),
            &mut needed,
            &mut count,
            Some(&mut resume),
            PCWSTR::null(),
        )
        .is_err()
        {
            let _ = CloseServiceHandle(scm);
            return;
        }
        let list = std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
        let mut cfg_buf = vec![0u8; 8192];
        for s in list {
            let name = wstr(s.lpServiceName).unwrap_or_default();
            let display = wstr(s.lpDisplayName).unwrap_or_else(|| name.clone());
            let running = s.ServiceStatusProcess.dwCurrentState.0 == 4;
            let (mut cmd, mut start, mut account) = (String::new(), None, None);
            if let Ok(h) = OpenServiceW(scm, s.lpServiceName, SERVICE_QUERY_CONFIG) {
                let mut need = 0u32;
                let ok = QueryServiceConfigW(
                    h,
                    Some(cfg_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
                    cfg_buf.len() as u32,
                    &mut need,
                )
                .is_ok();
                if ok {
                    let c = &*(cfg_buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
                    cmd = wstr(c.lpBinaryPathName).unwrap_or_default();
                    account = wstr(c.lpServiceStartName);
                    start = Some(
                        match c.dwStartType.0 {
                            0 => "önyükleme",
                            1 => "sistem",
                            2 => "otomatik",
                            3 => "elle",
                            4 => "devre dışı",
                            _ => "bilinmiyor",
                        }
                        .to_string(),
                    );
                }
                let _ = CloseServiceHandle(h);
            }
            let mut it = item("service", "Hizmet Denetimi Yöneticisi", &name, &cmd);
            it.name = if display != name { format!("{display} ({name})") } else { name.clone() };
            it.id = format!("service|scm|{}", name.to_ascii_lowercase());
            it.enabled = start.as_deref() != Some("devre dışı");
            it.start = start;
            it.state = Some(if running { "çalışıyor" } else { "durdu" }.into());
            it.account = account;
            out.push(it);
        }
        let _ = CloseServiceHandle(scm);
    }
}

// ---------------- scheduled tasks ----------------

unsafe fn walk_tasks(folder: &ITaskFolder, out: &mut Vec<StartupItem>, depth: u32) {
    if depth > 12 {
        return;
    }
    if let Ok(tasks) = folder.GetTasks(TASK_ENUM_HIDDEN.0) {
        let n = tasks.Count().unwrap_or(0);
        for i in 1..=n {
            let Ok(t) = tasks.get_Item(&VARIANT::from(i)) else { continue };
            let name = t.Name().map(|b| b.to_string()).unwrap_or_default();
            let path = t.Path().map(|b| b.to_string()).unwrap_or_default();
            let enabled = t.Enabled().map(|v| v.as_bool()).unwrap_or(true);
            let mut cmds = Vec::new();
            let mut author = None;
            if let Ok(def) = t.Definition() {
                if let Ok(ri) = def.RegistrationInfo() {
                    let mut a = BSTR::new();
                    if ri.Author(&mut a).is_ok() && !a.is_empty() {
                        author = Some(a.to_string());
                    }
                }
                if let Ok(actions) = def.Actions() {
                    let mut c = 0i32;
                    let _ = actions.Count(&mut c);
                    for j in 1..=c {
                        let Ok(a) = actions.get_Item(j) else { continue };
                        let mut ty = TASK_ACTION_EXEC;
                        if a.Type(&mut ty).is_err() || ty != TASK_ACTION_EXEC {
                            continue;
                        }
                        if let Ok(ex) = a.cast::<IExecAction>() {
                            let mut p = BSTR::new();
                            let mut args = BSTR::new();
                            let _ = ex.Path(&mut p);
                            let _ = ex.Arguments(&mut args);
                            let ps = p.to_string();
                            let cmd = if ps.contains(' ') && !ps.starts_with('"') { format!("\"{ps}\"") } else { ps };
                            cmds.push(if args.is_empty() { cmd } else { format!("{cmd} {args}") });
                        }
                    }
                }
            }
            if cmds.is_empty() {
                continue; // COM-handler tasks have no command line to inspect
            }
            let folder_path = path.rsplit_once('\\').map(|(f, _)| if f.is_empty() { "\\" } else { f }).unwrap_or("\\");
            let mut it = item("task", folder_path, &name, &cmds.join(" && "));
            it.id = format!("task|{}", path.to_ascii_lowercase());
            it.enabled = enabled;
            it.author = author;
            out.push(it);
        }
    }
    if let Ok(subs) = folder.GetFolders(0) {
        let n = subs.Count().unwrap_or(0);
        for i in 1..=n {
            if let Ok(f) = subs.get_Item(&VARIANT::from(i)) {
                walk_tasks(&f, out, depth + 1);
            }
        }
    }
}

fn task_items(out: &mut Vec<StartupItem>) {
    unsafe {
        let init = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
        let r: windows::core::Result<()> = (|| {
            let svc: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            let empty = VARIANT::default();
            svc.Connect(&empty, &empty, &empty, &empty)?;
            let root = svc.GetFolder(&BSTR::from("\\"))?;
            walk_tasks(&root, out, 0);
            Ok(())
        })();
        if let Err(e) = r {
            log::warn!("task scheduler: {e}");
        }
        if init {
            CoUninitialize();
        }
    }
}

pub fn scan() -> Vec<StartupItem> {
    let mut out = Vec::with_capacity(600);
    registry_items(&mut out);
    folder_items(&mut out);
    service_items(&mut out);
    task_items(&mut out);
    // de-duplicate ids (e.g. a value present in both Run views)
    let mut seen = std::collections::HashSet::new();
    out.retain(|i| seen.insert(i.id.clone()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_parsing() {
        std::env::set_var("SystemRoot", r"C:\Windows");
        assert_eq!(image_of(r#""C:\Program Files\App\app.exe" --min"#).as_deref(), Some(r"C:\Program Files\App\app.exe"));
        assert_eq!(image_of(r"C:\Program Files\App\app.exe --min").as_deref(), Some(r"C:\Program Files\App\app.exe"));
        assert_eq!(image_of(r"\SystemRoot\System32\svchost.exe -k x").as_deref(), Some(r"C:\Windows\System32\svchost.exe"));
        assert_eq!(image_of("rundll32.exe shell32.dll,Foo").as_deref(), Some(r"C:\Windows\System32\rundll32.exe"));
    }

    #[test]
    fn live_scan_finds_services_and_tasks() {
        let items = scan();
        assert!(items.iter().any(|i| i.kind == "service"), "no services");
        assert!(items.iter().any(|i| i.kind == "task"), "no tasks");
        let svc = items.iter().find(|i| i.id == "service|scm|eventlog").expect("EventLog service");
        assert!(svc.command.to_ascii_lowercase().contains("svchost"));
    }
}
