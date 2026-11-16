//! Authenticode verification. Checks the embedded signature first, then falls back to
//! the system catalog database (most Windows binaries are catalog-signed, not embedded).
//! Revocation checks are disabled and URL retrieval is cache-only, so this never hits
//! the network.

use std::ffi::c_void;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

use super::wide;
use crate::model::{SignatureInfo, SignatureState};

const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B0003u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B0001u32 as i32;

pub fn verify(path: &str) -> SignatureInfo {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2 | 0x4) // READ | WRITE | DELETE
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return SignatureInfo { state: SignatureState::Unknown, publisher: None },
    };
    let handle = HANDLE(file.as_raw_handle());
    let path_w = wide(path);

    let embedded = unsafe { verify_embedded(&path_w, handle) };
    match embedded {
        (0, publisher) => SignatureInfo { state: SignatureState::Signed, publisher },
        (code, publisher)
            if code == TRUST_E_NOSIGNATURE
                || code == TRUST_E_SUBJECT_FORM_UNKNOWN
                || code == TRUST_E_PROVIDER_UNKNOWN =>
        {
            match unsafe { verify_catalog(&path_w, handle) } {
                Some((0, p)) => SignatureInfo { state: SignatureState::Signed, publisher: p },
                Some((_, p)) => SignatureInfo { state: SignatureState::Invalid, publisher: p },
                None => match super::msix::verify(path) {
                    Some(pkg) => SignatureInfo { state: SignatureState::Signed, publisher: Some(format!("{} (MSIX paketi)", pkg.publisher)) },
                    None => SignatureInfo { state: SignatureState::Unsigned, publisher },
                },
            }
        }
        (_, publisher) => SignatureInfo { state: SignatureState::Invalid, publisher },
    }
}

unsafe fn run_trust(data: &mut WINTRUST_DATA) -> (i32, Option<String>) {
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    let code = WinVerifyTrust(HWND::default(), &mut action, data as *mut _ as *mut c_void);
    let publisher = signer_name(data.hWVTStateData);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(HWND::default(), &mut action, data as *mut _ as *mut c_void);
    (code, publisher)
}

unsafe fn signer_name(state: HANDLE) -> Option<String> {
    if state.is_invalid() || state.0.is_null() {
        return None;
    }
    let prov = WTHelperProvDataFromStateData(state);
    if prov.is_null() {
        return None;
    }
    let signer = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
    if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
        return None;
    }
    let cert = (*(*signer).pasCertChain).pCert;
    if cert.is_null() {
        return None;
    }
    let mut buf = [0u16; 256];
    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
    if n <= 1 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..(n as usize - 1)]))
}

unsafe fn base_data() -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    }
}

unsafe fn verify_embedded(path_w: &[u16], handle: HANDLE) -> (i32, Option<String>) {
    let mut fi = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_w.as_ptr()),
        hFile: handle,
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = base_data();
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut fi };
    run_trust(&mut data)
}

/// Returns None when the file's hash is not in any system catalog.
unsafe fn verify_catalog(path_w: &[u16], handle: HANDLE) -> Option<(i32, Option<String>)> {
    let mut admin: isize = 0;
    let alg = wide("SHA256");
    CryptCATAdminAcquireContext2(&mut admin, None, PCWSTR(alg.as_ptr()), None, None).ok()?;

    let result = (|| {
        let mut size: u32 = 0;
        let _ = CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, None, None);
        if size == 0 || size > 128 {
            return None;
        }
        let mut hash = vec![0u8; size as usize];
        CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, Some(hash.as_mut_ptr()), None)
            .ok()?;
        let cat = CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None);
        if cat == 0 {
            return None;
        }
        let mut info = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        let out = if CryptCATCatalogInfoFromContext(cat, &mut info, 0).is_ok() {
            let tag = wide(&hex::encode_upper(&hash));
            let mut ci = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                pcwszMemberTag: PCWSTR(tag.as_ptr()),
                pcwszMemberFilePath: PCWSTR(path_w.as_ptr()),
                hMemberFile: handle,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: size,
                hCatAdmin: admin,
                ..Default::default()
            };
            let mut data = base_data();
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.Anonymous = WINTRUST_DATA_0 { pCatalog: &mut ci };
            Some(run_trust(&mut data))
        } else {
            None
        };
        let _ = CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        out
    })();
    let _ = CryptCATAdminReleaseContext(admin, 0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_signed_system_binary() {
        let r = verify(r"C:\Windows\System32\notepad.exe");
        assert_eq!(r.state, SignatureState::Signed, "{r:?}");
        assert!(r.publisher.unwrap_or_default().contains("Microsoft"));
    }

    #[test]
    fn embedded_signed_binary() {
        let r = verify(r"C:\Windows\System32\ntoskrnl.exe");
        assert_eq!(r.state, SignatureState::Signed, "{r:?}");
    }

    #[test]
    fn unsigned_file() {
        let p = std::env::temp_dir().join("gm_unsigned_test.exe");
        std::fs::write(&p, b"MZ not really a pe").unwrap();
        let r = verify(&p.to_string_lossy());
        assert_ne!(r.state, SignatureState::Signed);
        let _ = std::fs::remove_file(p);
    }
}
