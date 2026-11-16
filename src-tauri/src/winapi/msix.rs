//! MSIX / Microsoft Store packages carry their signature in the package (AppxSignature.p7x),
//! not in each executable, so Authenticode reports their files as unsigned.
//!
//! A file counts as package-signed when:
//!   1. it lives under `<ProgramFiles>\WindowsApps\<PackageFullName>\…`, and
//!   2. Windows has a package registered under exactly that full name whose install
//!      folder is that same directory (GetPackagePathByFullName).
//! Windows verifies the package signature at deployment and the WindowsApps tree is
//! writable only by TrustedInstaller, so a look-alike folder elsewhere — or an
//! unregistered folder dropped into WindowsApps — fails these checks.

use windows::core::PCWSTR;
use windows::Win32::Storage::Packaging::Appx::GetPackagePathByFullName;

use super::wide;

#[derive(Debug, Clone, PartialEq)]
pub struct PackageInfo {
    pub full_name: String,
    pub publisher: String,
}

/// `C:\Program Files\WindowsApps\Name_1.0_x64__hash\app\x.exe` → (root dir, full name).
pub fn package_root(path: &str) -> Option<(String, String)> {
    let lower = path.to_ascii_lowercase();
    let marker = "\\windowsapps\\";
    let i = lower.find(marker)?;
    // Only the machine-wide package store, not the per-user execution-alias folder.
    if lower[..i].contains("\\appdata\\") {
        return None;
    }
    let rest = &path[i + marker.len()..];
    let name = rest.split('\\').next()?;
    // Full names have the form Name_Version_Arch_ResourceId_PublisherId.
    if name.matches('_').count() < 4 || !rest.contains('\\') {
        return None;
    }
    Some((path[..i + marker.len() + name.len()].to_string(), name.to_string()))
}

fn registered_path(full_name: &str) -> Option<String> {
    let w = wide(full_name);
    let mut len = 0u32;
    unsafe {
        let _ = GetPackagePathByFullName(PCWSTR(w.as_ptr()), &mut len, None);
        if len == 0 || len > 4096 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        if GetPackagePathByFullName(PCWSTR(w.as_ptr()), &mut len, Some(windows::core::PWSTR(buf.as_mut_ptr()))).is_err() {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())]))
    }
}

pub fn verify(path: &str) -> Option<PackageInfo> {
    let (root, full_name) = package_root(path)?;
    let reg = registered_path(&full_name)?;
    if !reg.trim_end_matches('\\').eq_ignore_ascii_case(root.trim_end_matches('\\')) {
        return None;
    }
    let manifest = std::fs::read_to_string(format!("{root}\\AppxManifest.xml")).unwrap_or_default();
    Some(PackageInfo { full_name, publisher: publisher_from_manifest(&manifest) })
}

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let a = xml.find(&open)? + open.len();
    let b = xml[a..].find('<')?;
    Some(xml[a..a + b].trim())
}

/// Display name, unless it is a localised resource reference; then the certificate subject.
pub fn publisher_from_manifest(xml: &str) -> String {
    if let Some(n) = tag(xml, "PublisherDisplayName").filter(|n| !n.is_empty() && !n.starts_with("ms-resource:")) {
        return n.to_string();
    }
    if let Some(i) = xml.find("Publisher=\"") {
        let v = &xml[i + 11..];
        let v = &v[..v.find('"').unwrap_or(v.len())];
        for part in v.split(',') {
            let p = part.trim();
            if let Some(o) = p.strip_prefix("O=").or_else(|| p.strip_prefix("CN=")) {
                return o.trim_matches('"').to_string();
            }
        }
    }
    "MSIX paketi".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_parsing() {
        let p = r"C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2642.101.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe";
        let (root, name) = package_root(p).unwrap();
        assert_eq!(name, "5319275A.WhatsAppDesktop_2.2642.101.0_x64__cv1g1gvanyjgm");
        assert!(root.ends_with("cv1g1gvanyjgm"));
        assert!(package_root(r"C:\Users\x\AppData\Local\Microsoft\WindowsApps\Foo_1_x_y_z\a.exe").is_none());
        assert!(package_root(r"C:\Program Files\WindowsApps\evil\a.exe").is_none());
        assert!(package_root(r"C:\Temp\WindowsApps_fake\a.exe").is_none());
    }

    #[test]
    fn publisher_name() {
        assert_eq!(publisher_from_manifest("<Properties><PublisherDisplayName>WhatsApp Inc.</PublisherDisplayName>"), "WhatsApp Inc.");
        let x = r#"<Identity Name="a" Publisher="CN=Contoso, O=Contoso Ltd, C=US"/><PublisherDisplayName>ms-resource:pub</PublisherDisplayName>"#;
        assert_eq!(publisher_from_manifest(x), "Contoso");
    }

    #[test]
    fn fake_package_folder_is_rejected() {
        // Right shape, but no such package is registered.
        assert_eq!(verify(r"C:\Program Files\WindowsApps\Evil.App_1.0.0.0_x64__abcdefghijklm\evil.exe"), None);
    }

    /// Live check against Store apps seen on the development machine (skipped elsewhere).
    #[test]
    fn real_installed_package_is_recognised() {
        for p in [
            r"C:\Program Files\WindowsAppsř9275A.WhatsAppDesktop_2.2642.101.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe",
            r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.29.380.0_x64__8wekyb3d8bbwe\WindowsPackageManagerServer.exe",
        ] {
            if std::path::Path::new(p).exists() {
                let info = verify(p).expect(p);
                eprintln!("{p} -> {info:?}");
                assert!(!info.publisher.is_empty());
            }
        }
    }
}
