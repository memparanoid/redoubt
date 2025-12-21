// // Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// // SPDX-License-Identifier: GPL-3.0-only
// // See LICENSE in the repository root for full license text.

// // Platform support:
// //  - aarch64 (Linux, macOS, Windows ARM64): ASM implementation
// //  - x86_64 (Linux, macOS with SysV ABI): ASM implementation

use crate::error::HkdfError;

/// HKDF-SHA256 key derivation (assembly implementation)
#[cfg(any(
    all(target_arch = "aarch64", not(target_family = "wasm")),
    all(
        target_arch = "x86_64",
        any(target_os = "linux", target_os = "macos"),
        not(target_family = "wasm")
    )
))]
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
    // RFC 5869: okm_len must not exceed 255 * HashLen (255 * 32 = 8160 for SHA-256)
    const MAX_OUTPUT_LEN: usize = 255 * 32;
    if okm.len() > MAX_OUTPUT_LEN {
        return Err(HkdfError::OutputTooLong);
    }

    // Early return for zero-length output (valid, but no-op)
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

/// HKDF-SHA256 key derivation (unsupported platforms)
#[cfg(not(any(
    all(target_arch = "aarch64", not(target_family = "wasm")),
    all(
        target_arch = "x86_64",
        any(target_os = "linux", target_os = "macos"),
        not(target_family = "wasm")
    )
)))]
pub fn hkdf(_salt: &[u8], _ikm: &[u8], _info: &[u8], _okm: &mut [u8]) -> Result<(), HkdfError> {
    unreachable!("Unsupported platform. Supported: aarch64 (all OS), x86_64 (Linux/macOS)")
}
