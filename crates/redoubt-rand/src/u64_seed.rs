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

use core::fmt;

use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizeOnDropSentinel};

use crate::error::EntropyError;

/// A u64 seed with automatic zeroization on drop.
///
/// `U64Seed` ensures that entropy values are handled securely:
/// - Debug output is redacted
/// - Memory is zeroized on drop via sentinel
/// - Provides controlled drain operations that zeroize sources
///
/// # Example
///
/// ```rust
/// use redoubt_rand::u64_seed::U64Seed;
///
/// let mut seed = U64Seed::new();
/// seed.generate().expect("Failed to generate seed");
/// let value = seed.expose();
/// ```
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub struct U64Seed {
    value: u64,
    __sentinel: ZeroizeOnDropSentinel,
}

impl U64Seed {
    /// Creates a new zero-initialized seed.
    pub fn new() -> Self {
        Self {
            value: 0,
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Generates entropy from the best available hardware or OS source.
    ///
    /// Writes directly to internal storage to avoid stack copies.
    ///
    /// # Errors
    ///
    /// Returns `EntropyError::EntropyNotAvailable` if entropy cannot be obtained.
    pub fn generate(&mut self) -> Result<(), EntropyError> {
        get_entropy_u64_internal(self)
    }

    /// Drains a u64 value, zeroizing the source.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_rand::u64_seed::U64Seed;
    ///
    /// let mut source = 0x1234567890ABCDEFu64;
    /// let mut seed = U64Seed::new();
    /// seed.drain_from(&mut source);
    ///
    /// assert_eq!(seed.expose(), 0x1234567890ABCDEF);
    /// assert_eq!(source, 0); // zeroized
    /// ```
    pub fn drain_from(&mut self, src: &mut u64) {
        self.value = *src;
        src.fast_zeroize();
    }

    /// Drains from an 8-byte array, zeroizing the source.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_rand::u64_seed::U64Seed;
    ///
    /// let mut bytes = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    /// let mut seed = U64Seed::new();
    /// seed.drain_from_bytes(&mut bytes);
    ///
    /// assert_eq!(seed.expose(), 0xF0DEBC9A78563412u64); // little-endian
    /// assert_eq!(bytes, [0; 8]); // zeroized
    /// ```
    pub fn drain_from_bytes(&mut self, src: &mut [u8; 8]) {
        self.value = 0;
        for i in 0..8 {
            let byte = core::mem::take(&mut src[i]);
            self.value |= (byte as u64) << (i * 8);
        }
    }

    /// Exposes the seed value.
    ///
    /// The caller is responsible for handling the exposed value securely.
    pub fn expose(&self) -> u64 {
        self.value
    }
}

impl Default for U64Seed {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for U64Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "U64Seed([REDACTED])")
    }
}

/// Maximum retry attempts for hardware RNG instructions.
///
/// Hardware RNG can occasionally fail (e.g., underflow in entropy pool).
/// We retry a reasonable number of times before falling back.
#[cfg(target_arch = "x86_64")]
const MAX_RETRIES: usize = 10;

/// Obtains a u64 seed from the best available entropy source.
///
/// This is a convenience wrapper around `U64Seed::generate()`.
///
/// # Example
///
/// ```rust
/// use redoubt_rand::u64_seed::get_entropy_u64;
///
/// let seed = get_entropy_u64().expect("Failed to get entropy");
/// ```
pub fn get_entropy_u64() -> Result<u64, EntropyError> {
    let mut seed = U64Seed::new();
    seed.generate()?;
    Ok(seed.expose())
}

/// Internal function that writes entropy directly to a U64Seed.
///
/// This function attempts to use platform-specific hardware instructions
/// first, falling back to OS-provided sources if necessary.
///
/// # Platform-specific behavior
///
/// - **x86_64**: RDSEED → RDRAND → getrandom (cpufeatures detection)
/// - **aarch64**: Uses OS syscall (getentropy/getrandom)
/// - **wasm32**: crypto.getRandomValues from JS environment
/// - **Other**: getrandom syscall (covers RISC-V, s390x, PowerPC, etc.)
///
/// # Errors
///
/// Returns `EntropyError::EntropyNotAvailable` if entropy cannot be obtained.
fn get_entropy_u64_internal(seed: &mut U64Seed) -> Result<(), EntropyError> {
    #[cfg(target_arch = "x86_64")]
    {
        get_entropy_u64_x86_64(seed)
    }

    #[cfg(target_arch = "aarch64")]
    {
        get_entropy_u64_aarch64(seed)
    }

    #[cfg(target_arch = "wasm32")]
    {
        get_entropy_u64_wasm32(seed)
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "wasm32"
    )))]
    {
        get_entropy_u64_fallback(seed)
    }
}

// =============================================================================
// x86_64: RDSEED → RDRAND → getrandom
// =============================================================================

#[cfg(target_arch = "x86_64")]
mod x86_features {
    cpufeatures::new!(rdseed_cpuid, "rdseed");
    cpufeatures::new!(rdrand_cpuid, "rdrand");
}

/// Attempts to read entropy directly from RDSEED instruction.
///
/// RDSEED reads from the processor's entropy source and can occasionally
/// fail if the entropy pool is temporarily exhausted. Returns `true` if
/// successful and writes the value to `dst`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn try_rdseed(dst: *mut u64) -> bool {
    let mut value: u64;
    let success: u8;

    core::arch::asm!(
        "rdseed {value}",      // Read hardware entropy
        "setc {success}",      // CF=1 if success, 0 if underflow
        value = out(reg) value,
        success = out(reg_byte) success,
        options(nostack, nomem)
    );

    if success != 0 {
        core::ptr::write_volatile(dst, value);
        true
    } else {
        false
    }
}

/// Attempts to read pseudorandom from RDRAND instruction.
///
/// RDRAND reads from the processor's DRBG (seeded by hardware entropy).
/// Less secure than RDSEED but more widely available. Returns `true` if
/// successful and writes the value to `dst`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn try_rdrand(dst: *mut u64) -> bool {
    let mut value: u64;
    let success: u8;

    core::arch::asm!(
        "rdrand {value}",      // Read DRBG output
        "setc {success}",      // CF=1 if success, 0 if underflow
        value = out(reg) value,
        success = out(reg_byte) success,
        options(nostack, nomem)
    );

    if success != 0 {
        core::ptr::write_volatile(dst, value);
        true
    } else {
        false
    }
}

/// Gets entropy from x86_64 with hardware instruction hierarchy.
///
/// Tries in order:
/// 1. RDSEED (best: direct hardware entropy)
/// 2. RDRAND (good: DRBG seeded by hardware)
/// 3. getrandom/libc (fallback: OS syscall)
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn get_entropy_u64_x86_64(seed: &mut U64Seed) -> Result<(), EntropyError> {
    let dst = &mut seed.value as *mut u64;

    // Try RDSEED first (best option)
    if x86_features::rdseed_cpuid::get() {
        for _ in 0..MAX_RETRIES {
            if unsafe { try_rdseed(dst) } {
                return Ok(());
            }
        }
    }

    // Try RDRAND (fallback, more widely available)
    if x86_features::rdrand_cpuid::get() {
        for _ in 0..MAX_RETRIES {
            if unsafe { try_rdrand(dst) } {
                return Ok(());
            }
        }
    }

    // Final fallback to OS syscall
    get_entropy_u64_fallback(seed)
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
fn get_entropy_u64_aarch64(seed: &mut U64Seed) -> Result<(), EntropyError> {
    get_entropy_u64_fallback(seed)
}

// =============================================================================
// wasm32: crypto.getRandomValues
// =============================================================================

/// Gets entropy from WASM crypto.getRandomValues.
///
/// Uses getrandom crate which wraps JS crypto.getRandomValues.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
fn get_entropy_u64_wasm32(seed: &mut U64Seed) -> Result<(), EntropyError> {
    let mut bytes = [0u8; 8];

    getrandom::getrandom(&mut bytes).map_err(|_| EntropyError::EntropyNotAvailable)?;

    seed.drain_from_bytes(&mut bytes);
    Ok(())
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
fn get_entropy_u64_fallback(seed: &mut U64Seed) -> Result<(), EntropyError> {
    let mut bytes = [0u8; 8];

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let ret = unsafe {
            libc::getrandom(
                bytes.as_mut_ptr() as *mut libc::c_void,
                bytes.len(),
                0, // flags
            )
        };

        if ret == 8 {
            seed.drain_from_bytes(&mut bytes);
            return Ok(());
        } else {
            return Err(EntropyError::EntropyNotAvailable);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let ret = unsafe { libc::getentropy(bytes.as_mut_ptr() as *mut libc::c_void, bytes.len()) };

        if ret == 0 {
            seed.drain_from_bytes(&mut bytes);
            return Ok(());
        } else {
            return Err(EntropyError::EntropyNotAvailable);
        }
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        getrandom::fill(&mut bytes).map_err(|_| EntropyError::EntropyNotAvailable)?;
        seed.drain_from_bytes(&mut bytes);
        Ok(())
    }
}
