// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA256 implementation with secure memory handling.
//!
//! Selects the best available backend at compile time:
//! - x86_64 (Linux/macOS) with `asm` feature: assembly implementation
//! - aarch64 with `asm` feature: assembly implementation
//! - All other platforms: pure Rust implementation
//!
//! ## License
//!
//! GPL-3.0-only

#![no_std]
#![warn(missing_docs)]

#[cfg(test)]
mod tests;

pub use redoubt_hkdf_core::{HkdfApi, HkdfError};

/// HKDF-SHA256 key derivation (RFC 5869).
///
/// Automatically selects the best backend for the current platform.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
    #[cfg(all(
        feature = "asm",
        target_arch = "x86_64",
        any(target_os = "linux", target_os = "macos")
    ))]
    {
        redoubt_hkdf_x86::X86Backend.api_hkdf(salt, ikm, info, okm)
    }

    #[cfg(all(feature = "asm", target_arch = "aarch64"))]
    {
        redoubt_hkdf_arm::ArmBackend.api_hkdf(salt, ikm, info, okm)
    }

    #[cfg(not(any(
        all(
            feature = "asm",
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "macos")
        ),
        all(feature = "asm", target_arch = "aarch64")
    )))]
    {
        redoubt_hkdf_rust::RustBackend.api_hkdf(salt, ikm, info, okm)
    }
}
