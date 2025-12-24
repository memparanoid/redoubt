// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Platform support:
//  - aarch64 (Linux, macOS, Windows ARM64): ASM implementation
//  - x86_64 (Linux, macOS with SysV ABI): ASM implementation

use crate::error::HkdfError;

const MAX_OUTPUT_LEN: usize = 255 * 32;

/// HKDF-SHA256 key derivation (assembly implementation)
#[cfg(all(not(feature = "pure-rust"), is_asm_eligible))]
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
    if okm.len() > MAX_OUTPUT_LEN {
        return Err(HkdfError::OutputTooLong);
    }

    if okm.is_empty() {
        return Ok(());
    }

    unsafe {
        crate::asm::hkdf_sha256(
            salt.as_ptr(),
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
            info.as_ptr(),
            info.len(),
            okm.as_mut_ptr(),
            okm.len(),
        );
    }
    Ok(())
}

/// HKDF-SHA512 key derivation (Rust fallback)
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
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
    if okm.len() > MAX_OUTPUT_LEN {
        return Err(HkdfError::OutputTooLong);
    }

    if okm.is_empty() {
        return Ok(());
    }

    use crate::rust::hkdf::HkdfSha256State;

    let mut state = HkdfSha256State::new();
    state.derive(ikm, salt, info, okm);
    Ok(())
}
