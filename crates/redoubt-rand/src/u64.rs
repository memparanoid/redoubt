// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Secure u64 wrapper with automatic zeroization.

use core::fmt;

use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizeOnDropSentinel};

/// A u64 wrapper with automatic zeroization on drop.
///
/// `U64` ensures that sensitive u64 values are handled securely:
/// - Debug output is redacted
/// - Memory is zeroized on drop via sentinel
/// - Provides controlled drain operations that zeroize sources
///
/// # Example
///
/// ```rust
/// use redoubt_rand::u64::U64;
///
/// let mut value = U64::new();
/// // Use value...
/// // Automatically zeroized on drop
/// ```
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub struct U64 {
    value: u64,
    __sentinel: ZeroizeOnDropSentinel,
}

impl U64 {
    /// Creates a new zero-initialized value.
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            value: 0,
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Drains a u64 value, zeroizing the source.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_rand::u64::U64;
    ///
    /// let mut source = 0x1234567890ABCDEFu64;
    /// let mut value = U64::new();
    /// value.drain_from(&mut source);
    ///
    /// assert_eq!(value.expose(), 0x1234567890ABCDEF);
    /// assert_eq!(source, 0); // zeroized
    /// ```
    #[inline(always)]
    pub fn drain_from(&mut self, src: &mut u64) {
        self.value = *src;
        src.fast_zeroize();
    }

    /// Drains from an 8-byte array, zeroizing the source.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_rand::u64::U64;
    ///
    /// let mut bytes = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    /// let mut value = U64::new();
    /// value.drain_from_bytes(&mut bytes);
    ///
    /// assert_eq!(value.expose(), 0xF0DEBC9A78563412u64); // little-endian
    /// assert_eq!(bytes, [0; 8]); // zeroized
    /// ```
    #[inline(always)]
    pub fn drain_from_bytes(&mut self, src: &mut [u8; 8]) {
        self.value = 0;
        for i in 0..8 {
            let byte = core::mem::take(&mut src[i]);
            self.value |= (byte as u64) << (i * 8);
        }
    }

    /// Exposes the value.
    ///
    /// The caller is responsible for handling the exposed value securely.
    #[inline(always)]
    pub fn expose(&self) -> u64 {
        self.value
    }

    /// Returns a mutable pointer to the internal value.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is not used to create copies
    /// that outlive the U64 instance.
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u64 {
        &mut self.value as *mut u64
    }

    /// Performs xorshift operation in-place.
    ///
    /// Used internally by PRNG. Modifies the value without creating stack copies.
    #[inline(always)]
    pub(crate) fn xorshift(&mut self) {
        self.value ^= self.value << 13;
        self.value ^= self.value >> 7;
        self.value ^= self.value << 17;
    }
}

impl Default for U64 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for U64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "U64([REDACTED])")
    }
}
