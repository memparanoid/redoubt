// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Word32 - 32-bit word wrapper with guaranteed zeroization on drop.
//!
//! All operations are in-place to avoid stack temporaries.
//! SHA-256 functions use internal temporaries that are zeroized before return.

use redoubt_util::{u32_from_be, u32_to_be};
use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

/// 32-bit word wrapper with guaranteed zeroization.
///
/// - `#[repr(transparent)]` ensures same layout as u32
/// - Drop asserts zeroized (debug) then zeroizes (safety net)
/// - All operations are `_assign` variants for in-place mutation
#[derive(Default)]
#[repr(transparent)]
pub struct Word32(u32);

impl Word32 {
    /// Create new Word32 with given value
    #[inline(always)]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Create zero Word32
    #[inline(always)]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Copy value from another Word32
    #[inline(always)]
    pub fn copy_from(&mut self, src: &Word32) {
        self.0 = src.0;
    }

    /// Fill word with big-endian bytes, zeroizing source bytes
    #[inline(always)]
    pub fn fill_with_be_bytes(&mut self, bytes: &mut [u8; 4]) {
        u32_from_be(&mut self.0, bytes);
    }

    /// Export word as big-endian bytes, zeroizing self
    #[inline(always)]
    pub fn export_as_be_bytes(&mut self, bytes: &mut [u8; 4]) {
        u32_to_be(&mut self.0, bytes);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Arithmetic operations (in-place)
    // ═══════════════════════════════════════════════════════════════════════════

    /// self += rhs (wrapping)
    #[inline(always)]
    pub fn wrapping_add_assign(&mut self, rhs: &Word32) {
        self.0 = self.0.wrapping_add(rhs.0);
    }

    /// self += rhs (wrapping, raw value)
    #[inline(always)]
    pub fn wrapping_add_assign_val(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Bitwise operations (in-place)
    // ═══════════════════════════════════════════════════════════════════════════

    /// self ^= rhs
    #[inline(always)]
    pub fn xor_assign(&mut self, rhs: &Word32) {
        self.0 ^= rhs.0;
    }

    /// self &= rhs
    #[inline(always)]
    pub fn and_assign(&mut self, rhs: &Word32) {
        self.0 &= rhs.0;
    }

    /// self = !self
    #[inline(always)]
    pub fn not_assign(&mut self) {
        self.0 = !self.0;
    }

    /// self = self.rotate_right(n)
    #[inline(always)]
    pub fn rotate_right_assign(&mut self, n: u32) {
        self.0 = self.0.rotate_right(n);
    }

    /// self = self.rotate_left(n)
    #[inline(always)]
    pub fn rotate_left_assign(&mut self, n: u32) {
        self.0 = self.0.rotate_left(n);
    }

    /// self = self >> n
    #[inline(always)]
    pub fn shift_right_assign(&mut self, n: usize) {
        self.0 >>= n;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SHA-512 functions per RFC 6234 Section 5.3
    // Internal temporaries are zeroized before return.
    // ═══════════════════════════════════════════════════════════════════════════

    /// Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z) per RFC 6234 Section 5.3.1
    #[inline(always)]
    pub fn set_ch(out: &mut Word32, x: &Word32, y: &Word32, z: &Word32) {
        // t1 = x & y
        let mut t1 = Word32::zero();
        t1.copy_from(x);
        t1.and_assign(y);

        // t2 = !x & z
        let mut t2 = Word32::zero();
        t2.copy_from(x);
        t2.not_assign();
        t2.and_assign(z);

        // out = t1 ^ t2
        out.fast_zeroize();
        out.xor_assign(&t1);
        out.xor_assign(&t2);

        // Zeroize temporaries before drop
        t1.fast_zeroize();
        t2.fast_zeroize();
    }

    /// Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z) per RFC 6234 Section 5.3.2
    ///
    /// Optimized form: (x & y) ^ (z & (x ^ y))
    #[inline(always)]
    pub fn set_maj(out: &mut Word32, x: &Word32, y: &Word32, z: &Word32) {
        // xy = x & y
        let mut xy = Word32::zero();
        xy.copy_from(x);
        xy.and_assign(y);

        // z_and_x_xor_y = z & (x ^ y)
        let mut z_and_x_xor_y = Word32::zero();
        z_and_x_xor_y.copy_from(x);
        z_and_x_xor_y.xor_assign(y);
        z_and_x_xor_y.and_assign(z);

        // out = xy ^ (z & (x ^ y))
        out.fast_zeroize();
        out.xor_assign(&xy);
        out.xor_assign(&z_and_x_xor_y);

        // Zeroize temporaries before drop
        xy.fast_zeroize();
        z_and_x_xor_y.fast_zeroize();
    }

    /// Σ0(x) = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x) per RFC 6234 Section 5.1
    #[inline(always)]
    pub fn set_bsig0(out: &mut Word32, x: &Word32) {
        let mut v = Word32::zero();
        v.copy_from(x);

        out.fast_zeroize();

        // ROTR^2(x)
        v.rotate_right_assign(2);
        out.xor_assign(&v);
        v.rotate_left_assign(2); // restore x

        // ROTR^13(x)
        v.rotate_right_assign(13);
        out.xor_assign(&v);
        v.rotate_left_assign(13); // restore x

        // ROTR^22(x)
        v.rotate_right_assign(22);
        out.xor_assign(&v);

        v.fast_zeroize();
    }

    /// Σ1(x) = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x) per RFC 6234 Section 5.1
    #[inline(always)]
    pub fn set_bsig1(out: &mut Word32, x: &Word32) {
        let mut v = Word32::zero();
        v.copy_from(x);

        out.fast_zeroize();

        // ROTR^6(x)
        v.rotate_right_assign(6);
        out.xor_assign(&v);
        v.rotate_left_assign(6); // restore x

        // ROTR^11(x)
        v.rotate_right_assign(11);
        out.xor_assign(&v);
        v.rotate_left_assign(11); // restore x

        // ROTR^25(x)
        v.rotate_right_assign(25);
        out.xor_assign(&v);

        v.fast_zeroize();
    }

    /// σ0(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x) per RFC 6234 Section 5.1
    #[inline(always)]
    pub fn set_ssig0(out: &mut Word32, x: &Word32) {
        let mut v_rot = Word32::zero();
        v_rot.copy_from(x);
        let mut v_shr = Word32::zero();
        v_shr.copy_from(x);

        out.fast_zeroize();

        // ROTR^7(x)
        v_rot.rotate_right_assign(7);
        out.xor_assign(&v_rot);
        v_rot.rotate_left_assign(7); // restore x

        // ROTR^18(x)
        v_rot.rotate_right_assign(18);
        out.xor_assign(&v_rot);
        v_rot.fast_zeroize();

        // SHR^3(x)
        v_shr.shift_right_assign(3);
        out.xor_assign(&v_shr);
        v_shr.fast_zeroize();
    }

    /// σ1(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x) per RFC 6234 Section 5.1
    #[inline(always)]
    pub fn set_ssig1(out: &mut Word32, x: &Word32) {
        let mut v_rot = Word32::zero();
        v_rot.copy_from(x);
        let mut v_shr = Word32::zero();
        v_shr.copy_from(x);

        out.fast_zeroize();

        // ROTR^17(x)
        v_rot.rotate_right_assign(17);
        out.xor_assign(&v_rot);
        v_rot.rotate_left_assign(17); // restore x

        // ROTR^19(x)
        v_rot.rotate_right_assign(19);
        out.xor_assign(&v_rot);
        v_rot.fast_zeroize();

        // SHR^10(x)
        v_shr.shift_right_assign(10);
        out.xor_assign(&v_shr);
        v_shr.fast_zeroize();
    }

    /// Get mutable reference to inner u32
    #[inline(always)]
    pub(crate) fn as_mut_u32(&mut self) -> &mut u32 {
        &mut self.0
    }

    /// Get inner u32 value for testing/assertions only
    #[cfg(test)]
    #[inline(always)]
    pub(crate) fn as_u32(&self) -> u32 {
        self.0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Zeroization traits
// ═══════════════════════════════════════════════════════════════════════════════

impl FastZeroizable for Word32 {
    fn fast_zeroize(&mut self) {
        self.0.fast_zeroize();
    }
}

impl ZeroizeMetadata for Word32 {
    const CAN_BE_BULK_ZEROIZED: bool = true;
}

impl ZeroizationProbe for Word32 {
    fn is_zeroized(&self) -> bool {
        self.0.is_zeroized()
    }
}

impl Drop for Word32 {
    fn drop(&mut self) {
        // Debug: assert was properly zeroized before drop
        debug_assert!(self.is_zeroized(), "Word32 dropped without zeroization");
        // Safety net: zeroize anyway
        self.fast_zeroize();
    }
}
