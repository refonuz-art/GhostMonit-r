pub mod dpapi;
pub mod msix;
pub mod elevation;
pub mod signature;
pub mod tcp_table;

/// Encode a Rust str as a NUL-terminated UTF-16 buffer.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

