// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AES-NI intrinsics for x86_64.

use core::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_and_si128, _mm_loadu_si128, _mm_setzero_si128,
    _mm_storeu_si128, _mm_xor_si128,
};

use memzer::{Zeroizable, ZeroizationProbe};
use zeroize::Zeroize;

/// AES block using AES-NI intrinsics.
///
/// Does NOT implement Copy to prevent unzeroized copies.
/// Caller must ensure CPU supports AES-NI before calling any method.
#[repr(transparent)]
pub struct Intrinsics(__m128i);

impl Intrinsics {
    /// Create a zeroed block.
    #[inline]
    #[target_feature(enable = "aes")]
    pub fn zero() -> Self {
        Self(unsafe { _mm_setzero_si128() })
    }

    /// Load 16 bytes into a block.
    #[inline]
    #[target_feature(enable = "aes")]
    pub fn load(bytes: &[u8; 16]) -> Self {
        Self(unsafe { _mm_loadu_si128(bytes.as_ptr() as *const __m128i) })
    }

    /// Store block to 16 bytes.
    #[inline]
    #[target_feature(enable = "aes")]
    pub fn store(&self, out: &mut [u8; 16]) {
        unsafe { _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, self.0) }
    }

    /// XOR two blocks.
    #[inline]
    #[target_feature(enable = "aes")]
    pub fn xor(&self, other: &Self) -> Self {
        Self(unsafe { _mm_xor_si128(self.0, other.0) })
    }

    /// AND two blocks.
    #[inline]
    #[target_feature(enable = "aes")]
    pub fn and(&self, other: &Self) -> Self {
        Self(unsafe { _mm_and_si128(self.0, other.0) })
    }

    /// AES encryption round: SubBytes + ShiftRows + MixColumns + XOR round_key
    #[inline]
    #[target_feature(enable = "aes")]
    pub fn aes_enc(&self, round_key: &Self) -> Self {
        Self(unsafe { _mm_aesenc_si128(self.0, round_key.0) })
    }
}

impl Zeroize for Intrinsics {
    #[inline]
    fn zeroize(&mut self) {
        // Overwrite SIMD register with zeros
        self.0 = unsafe { _mm_setzero_si128() };
    }
}

impl Drop for Intrinsics {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Default for Intrinsics {
    #[inline]
    fn default() -> Self {
        Self(unsafe { _mm_setzero_si128() })
    }
}

impl ZeroizationProbe for Intrinsics {
    #[inline]
    fn is_zeroized(&self) -> bool {
        let mut bytes = [0u8; 16];
        unsafe { _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, self.0) };
        bytes.iter().all(|&b| b == 0)
    }
}

impl Zeroizable for Intrinsics {
    #[inline]
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}
