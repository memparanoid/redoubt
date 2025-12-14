// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AES-NI intrinsics for x86_64.

use core::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_and_si128, _mm_loadu_si128, _mm_setzero_si128, _mm_storeu_si128,
    _mm_xor_si128,
};

use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

/// AES block using AES-NI intrinsics.
///
/// Does NOT implement Copy - caller must manually zeroize before drop.
/// Drop asserts the value is zero (in debug/test builds).
#[repr(transparent)]
pub struct Intrinsics(__m128i);

impl Intrinsics {
    /// Load 16 bytes into a block.
    #[inline(always)]
    pub fn load(bytes: &[u8; 16]) -> Self {
        Self(unsafe { _mm_loadu_si128(bytes.as_ptr() as *const __m128i) })
    }

    /// Store block to 16 bytes.
    #[inline(always)]
    pub fn store(&self, out: &mut [u8; 16]) {
        unsafe { _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, self.0) };
    }

    /// XOR two blocks.
    #[inline(always)]
    pub fn xor(&self, other: &Self) -> Self {
        Self(unsafe { _mm_xor_si128(self.0, other.0) })
    }

    /// AND two blocks.
    #[inline(always)]
    pub fn and(&self, other: &Self) -> Self {
        Self(unsafe { _mm_and_si128(self.0, other.0) })
    }

    /// AES encryption round: SubBytes + ShiftRows + MixColumns + XOR round_key
    #[inline(always)]
    pub fn aes_enc(&self, round_key: &Self) -> Self {
        Self(unsafe { _mm_aesenc_si128(self.0, round_key.0) })
    }

    // === In-place operations ===

    /// Move value to dest, zeroizing both old dest and self.
    #[inline(always)]
    pub fn move_to(&mut self, dest: &mut Self) {
        core::mem::swap(self, dest);
        self.fast_zeroize();
    }

    /// XOR in-place: self = self ^ other
    #[inline(always)]
    pub fn xor_in_place(&mut self, other: &Self) {
        self.0 = unsafe { _mm_xor_si128(self.0, other.0) };
    }

    /// AND in-place: self = self & other
    #[inline(always)]
    pub fn and_in_place(&mut self, other: &Self) {
        self.0 = unsafe { _mm_and_si128(self.0, other.0) };
    }

    /// AES encryption round in-place: self = AES(self, round_key)
    #[inline(always)]
    pub fn aes_enc_in_place(&mut self, round_key: &Self) {
        self.0 = unsafe { _mm_aesenc_si128(self.0, round_key.0) };
    }
}

impl ZeroizeMetadata for Intrinsics {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for Intrinsics {
    #[inline]
    fn fast_zeroize(&mut self) {
        // Overwrite register with zeros
        self.0 = unsafe { _mm_setzero_si128() };
    }
}

impl Drop for Intrinsics {
    #[inline]
    fn drop(&mut self) {
        debug_assert!(
            self.is_zeroized(),
            "Intrinsics dropped without zeroization!"
        );
    }
}

impl ZeroizationProbe for Intrinsics {
    #[inline]
    fn is_zeroized(&self) -> bool {
        let mut bytes = [0u8; 16];
        unsafe { _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, self.0) };
        let is_zeroized = bytes.is_zeroized();
        bytes.fast_zeroize();
        is_zeroized
    }
}

impl core::fmt::Debug for Intrinsics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Intrinsics (x86_64) {{ [protected] }}")
    }
}
