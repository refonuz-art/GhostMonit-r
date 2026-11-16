//! Windows DPAPI: secrets (API keys) are encrypted to the current Windows user
//! before they touch the database. Never stored in plain text.

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

const ENTROPY: &[u8] = b"GhostMonitor.v1.secret";

fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: b.len() as u32, pbData: b.as_ptr() as *mut u8 }
}

unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
    let _ = LocalFree(Some(HLOCAL(out.pbData as *mut _)));
    v
}

pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
    let input = blob(plain);
    let ent = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(&input, None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            .map_err(|e| e.message())?;
        Ok(take(out))
    }
}

pub fn unprotect(cipher: &[u8]) -> Result<Vec<u8>, String> {
    let input = blob(cipher);
    let ent = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(&input, None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            .map_err(|e| e.message())?;
        Ok(take(out))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let c = super::protect(b"secret-key-123").unwrap();
        assert!(!c.windows(14).any(|w| w == b"secret-key-123"));
        assert_eq!(super::unprotect(&c).unwrap(), b"secret-key-123");
    }
}
