// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Direct entropy extraction for u64 seeds via OS syscalls.
//!
//! This module provides platform-specific implementations for obtaining
//! high-quality entropy by writing directly to the caller's pointer,
//! avoiding intermediate buffers that could leave traces in memory.
//!
//! # Architecture Support
//!
//! - **Linux/Android**: `libc::getrandom()` syscall direct to pointer
//! - **macOS/iOS**: `libc::getentropy()` direct to pointer
//! - **wasm32**: JS `crypto.getRandomValues`
//! - **Other**: `getrandom` crate fallback
//!
//! # Security Model
//!
//! All platforms write directly to the provided `*mut u64` pointer without
//! intermediate copies. The OS kernel writes entropy straight into the
//! caller's memory, ensuring no temporary buffers hold sensitive material.
//!
//! The entropy obtained here is used as HKDF salt combined with OS entropy
//! (IKM) to derive final keys. Since seeds are ephemeral and immediately
//! zeroized, even if an attacker obtains the original IKM from a memory
//! dump, they cannot reconstruct the derived key without the seeds.

use crate::error::EntropyError;

/// Generates entropy from the best available OS source.
///
/// Writes directly to the provided pointer to avoid stack copies.
///
/// # Platform-specific behavior
///
/// - **Linux/Android**: `getrandom()` syscall (blocks until entropy available)
/// - **macOS/iOS**: `getentropy()` (always succeeds for ≤256 bytes)
/// - **wasm32**: `crypto.getRandomValues` from JS environment
/// - **Other**: `getrandom` crate
///
/// # Safety
///
/// Caller must ensure `dst` points to valid, aligned u64 storage.
///
/// # Errors
///
/// Returns `EntropyError::EntropyNotAvailable` if entropy cannot be obtained.
///
/// # Example
///
/// ```rust
/// use redoubt_rand::u64_seed::generate;
///
/// let mut seed = 0u64;
/// unsafe { generate(&mut seed as *mut u64).expect("Failed to generate entropy") };
/// ```
pub unsafe fn generate(dst: *mut u64) -> Result<(), EntropyError> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let ret = unsafe { libc::getrandom(dst as *mut libc::c_void, 8, 0) };
        finalize_getrandom(ret)
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let ret = unsafe { libc::getentropy(dst as *mut libc::c_void, 8) };
        finalize_getentropy(ret)
    }

    #[cfg(target_arch = "wasm32")]
    {
        let slice = unsafe { core::slice::from_raw_parts_mut(dst as *mut u8, 8) };
        getrandom::fill(slice).map_err(|_| EntropyError::EntropyNotAvailable)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_arch = "wasm32"
    )))]
    {
        let slice = unsafe { core::slice::from_raw_parts_mut(dst as *mut u8, 8) };
        getrandom::fill(slice).map_err(|_| EntropyError::EntropyNotAvailable)?;

        Ok(())
    }
}

#[inline(always)]
pub(crate) fn finalize_getrandom(ret: isize) -> Result<(), EntropyError> {
    if ret == 8 {
        Ok(())
    } else {
        Err(EntropyError::EntropyNotAvailable)
    }
}

#[inline(always)]
#[allow(unused)]
pub(crate) fn finalize_getentropy(ret: i32) -> Result<(), EntropyError> {
    if ret == 0 {
        Ok(())
    } else {
        Err(EntropyError::EntropyNotAvailable)
    }
}
