// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Direct hardware entropy extraction for u64 seeds.
//!
//! This module provides platform-specific implementations for obtaining
//! high-quality entropy directly from hardware sources. The goal is to
//! minimize the attack surface by avoiding intermediate buffers and using
//! CPU instructions where possible.
//!
//! # Architecture Support
//!
//! - **x86_64**: RDSEED → RDRAND → getrandom (with cpufeatures detection)
//! - **aarch64**: RNDR → getrandom (with aarch64-cpu detection)
//! - **wasm32**: JS crypto.getRandomValues
//! - **Fallback**: getrandom syscall for all other architectures
//!
//! # Security Model
//!
//! The entropy obtained here is used to seed permutation algorithms that
//! obfuscate sensitive key material. Since the seeds are ephemeral (never
//! stored), even if an attacker obtains the original key material from a
//! memory dump, they cannot reverse the permutation without the seeds.
//!
//! # Why Not Just Use getrandom?
//!
//! Following Redoubt's zero-trust design principle, we prefer obtaining entropy
//! directly from hardware sources when possible. Multiple abstraction layers may
//! introduce intermediate copies in memory. Direct hardware instructions (RDSEED,
//! RDRAND, RNDR) provide the shortest path from entropy source to application.

use crate::error::EntropyError;

/// Maximum retry attempts for hardware RNG instructions.
///
/// Hardware RNG can occasionally fail (e.g., underflow in entropy pool).
/// We retry a reasonable number of times before falling back.
#[cfg(target_arch = "x86_64")]
const MAX_RETRIES: usize = 10;

/// Generates entropy from the best available hardware or OS source.
///
/// Writes directly to the provided pointer to avoid stack copies.
///
/// # Platform-specific behavior
///
/// - **x86_64**: RDSEED → RDRAND → getrandom (cpufeatures detection)
/// - **aarch64**: Uses OS syscall (getentropy/getrandom)
/// - **wasm32**: crypto.getRandomValues from JS environment
/// - **Other**: getrandom syscall (covers RISC-V, s390x, PowerPC, etc.)
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
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { get_entropy_u64_x86_64(dst) }
    }

    #[cfg(target_arch = "aarch64")]
    {
        unsafe { get_entropy_u64_aarch64(dst) }
    }

    #[cfg(target_arch = "wasm32")]
    {
        unsafe { get_entropy_u64_wasm32(dst) }
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "wasm32"
    )))]
    {
        unsafe { get_entropy_u64_fallback(dst) }
    }
}

// =============================================================================
// x86_64: RDSEED → RDRAND → getrandom
// =============================================================================

#[cfg(target_arch = "x86_64")]
cpufeatures::new!(x86_64_rdseed_cpuid, "rdseed");
#[cfg(target_arch = "x86_64")]
cpufeatures::new!(x86_64_rdrand_cpuid, "rdrand");

/// Attempts to read entropy directly from RDSEED instruction.
///
/// RDSEED reads from the processor's entropy source and can occasionally
/// fail if the entropy pool is temporarily exhausted. Returns `true` if
/// successful and writes the value to `dst`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn try_rdseed(dst: *mut u64) -> bool {
    let success: u8;

    unsafe {
        core::arch::asm!(
            "rdseed rax",
            "setc cl",
            "test cl, cl",
            "jz 2f",
            "mov [{dst}], rax",
            "2:",
            dst = in(reg) dst,
            out("rax") _,
            lateout("cl") success,
            options(nostack)
        );
    }

    success != 0
}

/// Attempts to read pseudorandom from RDRAND instruction.
///
/// RDRAND reads from the processor's DRBG (seeded by hardware entropy).
/// Less secure than RDSEED but more widely available. Returns `true` if
/// successful and writes the value to `dst`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn try_rdrand(dst: *mut u64) -> bool {
    let success: u8;

    unsafe {
        core::arch::asm!(
            "rdrand rax",
            "setc cl",
            "test cl, cl",
            "jz 2f",
            "mov [{dst}], rax",
            "2:",
            dst = in(reg) dst,
            out("rax") _,
            lateout("cl") success,
            options(nostack)
        );
    }

    success != 0
}

/// Gets entropy from x86_64 with hardware instruction hierarchy.
///
/// Tries in order:
/// 1. RDSEED (best: direct hardware entropy)
/// 2. RDRAND (good: DRBG seeded by hardware)
/// 3. getrandom/libc (fallback: OS syscall)
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn get_entropy_u64_x86_64(dst: *mut u64) -> Result<(), EntropyError> {
    // Try RDSEED first (best option)
    if x86_64_rdseed_cpuid::get() {
        for _ in 0..MAX_RETRIES {
            if try_rdseed(dst) {
                return Ok(());
            }
        }
    }

    // Try RDRAND (fallback, more widely available)
    if x86_64_rdrand_cpuid::get() {
        for _ in 0..MAX_RETRIES {
            if try_rdrand(dst) {
                return Ok(());
            }
        }
    }

    // Final fallback to OS syscall
    unsafe { get_entropy_u64_fallback(dst) }
}

// =============================================================================
// aarch64: RNDR → getrandom
// =============================================================================

/// Gets entropy from aarch64 using OS syscall.
///
/// ARM hardware entropy (RNDR) detection is unreliable across different CPUs.
/// We use libc syscalls directly (getentropy/getrandom) which are syscall
/// wrappers with minimal intermediate buffering.
///
/// This is a pragmatic trade-off: x86_64 gets full hardware optimization, while
/// ARM uses reliable kernel entropy. The double-permutation design (2^128 security)
/// remains strong even with kernel-sourced seeds.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn get_entropy_u64_aarch64(dst: *mut u64) -> Result<(), EntropyError> {
    unsafe { get_entropy_u64_fallback(dst) }
}

// =============================================================================
// wasm32: crypto.getRandomValues
// =============================================================================

/// Gets entropy from WASM crypto.getRandomValues.
///
/// Uses getrandom crate which wraps JS crypto.getRandomValues.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn get_entropy_u64_wasm32(dst: *mut u64) -> Result<(), EntropyError> {
    unsafe {
        getrandom::getrandom(core::slice::from_raw_parts_mut(
            dst as *mut u8,
            core::mem::size_of::<u64>(),
        ))
        .map_err(|_| EntropyError::EntropyNotAvailable)
    }
}

// =============================================================================
// Fallback: OS-specific syscalls
// =============================================================================

/// Fallback entropy source using OS-specific syscalls.
///
/// Prefers direct libc syscalls when available (Linux, macOS, etc.) for better
/// reliability and less intermediate buffering. Falls back to getrandom crate
/// for Windows and other platforms.
#[inline(always)]
unsafe fn get_entropy_u64_fallback(dst: *mut u64) -> Result<(), EntropyError> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let ret = unsafe { libc::getrandom(dst as *mut libc::c_void, 8, 0) };

        if ret == 8 {
            return Ok(());
        } else {
            return Err(EntropyError::EntropyNotAvailable);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let ret = unsafe { libc::getentropy(dst as *mut libc::c_void, 8) };

        if ret == 0 {
            Ok(())
        } else {
            Err(EntropyError::EntropyNotAvailable)
        }
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        // getrandom crate requires a slice
        let slice = unsafe { core::slice::from_raw_parts_mut(dst as *mut u8, 8) };
        getrandom::fill(slice).map_err(|_| EntropyError::EntropyNotAvailable)?;

        Ok(())
    }
}

#[test]
fn debug_entropy_windows() {
    let mut seed = 0u64;

    #[cfg(target_arch = "x86_64")]
    {
        use crate::u64_seed::{x86_64_rdrand_cpuid, x86_64_rdseed_cpuid};
        println!("RDSEED available: {}", x86_64_rdseed_cpuid::get());
        println!("RDRAND available: {}", x86_64_rdrand_cpuid::get());
    }

    let result = unsafe { generate(&mut seed as *mut u64) };
    println!("Result: {:?}", result);
    println!("Seed value: 0x{:016x}", seed);

    assert!(result.is_ok());
    assert_ne!(seed, 0);
}
