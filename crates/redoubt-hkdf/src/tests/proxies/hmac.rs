// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HMAC-SHA256 proxy

/// HMAC-SHA256 (assembly implementation)
///
/// # Arguments
/// * `key` - HMAC key (arbitrary length)
/// * `data` - Input message (arbitrary length)
/// * `out` - Output MAC (32 bytes)
#[cfg(all(feature = "asm", is_asm_eligible))]
pub fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; 32]) {
    unsafe {
        crate::asm::hmac_sha256(
            key.as_ptr(),
            key.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
        );
    }
}

/// HMAC-SHA256 (Rust fallback)
#[cfg(not(all(feature = "asm", is_asm_eligible)))]
pub fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; 32]) {
    use crate::rust::hmac::HmacSha256State;

    let mut state = HmacSha256State::new();
    state.sha256(key, data, out);
}
