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
#[cfg(all(
    not(feature = "pure-rust"),
    any(
        all(target_arch = "aarch64", not(target_family = "wasm")),
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "macos"),
            not(target_family = "wasm")
        )
    )
))]
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
#[cfg(any(
    feature = "pure-rust",
    not(any(
        all(target_arch = "aarch64", not(target_family = "wasm")),
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "macos"),
            not(target_family = "wasm")
        )
    ))
))]
pub fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; 32]) {
    use crate::rust::hmac::HmacSha256State;

    let mut state = HmacSha256State::new();
    state.sha256(key, data, out);
}
