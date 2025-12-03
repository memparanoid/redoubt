// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ARM Crypto intrinsics for aarch64.

use core::arch::aarch64::{
    uint8x16_t, vaeseq_u8, vaesmcq_u8, vandq_u8, vdupq_n_u8, veorq_u8, vld1q_u8, vst1q_u8,
};

use memzer::ZeroizationProbe;
use zeroize::Zeroize;

/// AES block using ARM Crypto intrinsics.
///
/// Does NOT implement Copy - caller must manually zeroize before drop.
/// Drop asserts the value is zero (in debug/test builds).
#[repr(transparent)]
pub struct Intrinsics(uint8x16_t);

impl Intrinsics {
    /// Load 16 bytes into a block.
    #[inline(always)]
    pub fn load(bytes: &[u8; 16]) -> Self {
        Self(unsafe { vld1q_u8(bytes.as_ptr()) })
    }

    /// Store block to 16 bytes.
    #[inline(always)]
    pub fn store(&self, out: &mut [u8; 16]) {
        unsafe { vst1q_u8(out.as_mut_ptr(), self.0) };
    }

    /// XOR two blocks.
    #[inline(always)]
    pub fn xor(&self, other: &Self) -> Self {
        Self(unsafe { veorq_u8(self.0, other.0) })
    }

    /// AND two blocks.
    #[inline(always)]
    pub fn and(&self, other: &Self) -> Self {
        Self(unsafe { vandq_u8(self.0, other.0) })
    }

    /// AES encryption round: SubBytes + ShiftRows + MixColumns + XOR round_key
    #[inline(always)]
    pub fn aes_enc(&self, round_key: &Self) -> Self {
        unsafe {
            let zero = vdupq_n_u8(0);
            let after_sub_shift = vaeseq_u8(self.0, zero);
            let after_mix = vaesmcq_u8(after_sub_shift);
            Self(veorq_u8(after_mix, round_key.0))
        }
    }

    // === In-place operations ===

    /// Move value to dest, zeroizing both old dest and self.
    #[inline(always)]
    pub fn move_to(&mut self, dest: &mut Self) {
        core::mem::swap(self, dest);
        self.zeroize();
    }

    /// XOR in-place: self = self ^ other
    #[inline(always)]
    pub fn xor_in_place(&mut self, other: &Self) {
        self.0 = unsafe { veorq_u8(self.0, other.0) };
    }

    /// AND in-place: self = self & other
    #[inline(always)]
    pub fn and_in_place(&mut self, other: &Self) {
        self.0 = unsafe { vandq_u8(self.0, other.0) };
    }

    /// AES encryption round in-place: self = AES(self, round_key)
    #[inline(always)]
    pub fn aes_enc_in_place(&mut self, round_key: &Self) {
        unsafe {
            let zero = vdupq_n_u8(0);
            let after_sub_shift = vaeseq_u8(self.0, zero);
            let after_mix = vaesmcq_u8(after_sub_shift);
            self.0 = veorq_u8(after_mix, round_key.0);
        }
    }
}

impl Zeroize for Intrinsics {
    #[inline]
    fn zeroize(&mut self) {
        // Overwrite register with zeros
        self.0 = unsafe { vdupq_n_u8(0) };
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
        unsafe { vst1q_u8(bytes.as_mut_ptr(), self.0) };
        bytes.iter().all(|&b| b == 0)
    }
}

impl core::fmt::Debug for Intrinsics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Intrinsics (aarch64) {{ [protected] }}")
    }
}
