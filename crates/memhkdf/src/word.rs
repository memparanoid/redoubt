// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

#[repr(transparent)]
pub struct Word64(u64);

impl Word64 {
    #[inline(always)]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub const fn zero() -> Self {
        Self(0)
    }

    #[inline(always)]
    pub fn get(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    pub fn set(&mut self, value: u64) {
        self.0 = value;
    }

    #[inline(always)]
    pub fn wrapping_add_assign(&mut self, rhs: &Word64) {
        self.0 = self.0.wrapping_add(rhs.0);
    }

    #[inline(always)]
    pub fn wrapping_add_assign_val(&mut self, rhs: u64) {
        self.0 = self.0.wrapping_add(rhs);
    }

    #[inline(always)]
    pub fn xor_assign(&mut self, rhs: &Word64) {
        self.0 ^= rhs.0;
    }

    #[inline(always)]
    pub fn and_assign(&mut self, rhs: &Word64) {
        self.0 &= rhs.0;
    }

    #[inline(always)]
    pub fn not_assign(&mut self) {
        self.0 = !self.0;
    }

    #[inline(always)]
    pub fn rotate_right_assign(&mut self, n: u32) {
        self.0 = self.0.rotate_right(n);
    }

    #[inline(always)]
    pub fn rotate_left_assign(&mut self, n: u32) {
        self.0 = self.0.rotate_left(n);
    }

    #[inline(always)]
    pub fn shift_right_assign(&mut self, n: usize) {
        self.0 = self.0 >> n;
    }

    #[inline(always)]
    pub fn set_ch(out: &mut Word64, x: &Word64, y: &Word64, z: &Word64) {
        // t1 = x & y
        let mut t1 = Word64::new(x.get());
        t1.and_assign(y);

        // t2 = !x & z
        let mut t2 = Word64::new(x.get());
        t2.not_assign();
        t2.and_assign(z);

        // out = t1 ^ t2
        out.fast_zeroize();
        out.xor_assign(&t1);
        out.xor_assign(&t2);

        // Zeroize temporaries
        t1.fast_zeroize();
        t2.fast_zeroize();
    }

    /// Maj(x, y, z) = (x & y) ^ (z & (x ^ y))
    #[inline(always)]
    pub fn set_maj(out: &mut Word64, x: &Word64, y: &Word64, z: &Word64) {
        // xy = x & y
        let mut xy = Word64::new(x.get());
        xy.and_assign(y); // xy = x ∧ y

        // z_and_x_xor_y = z & (x ^ y)
        let mut z_and_x_xor_y = Word64::new(x.get());
        z_and_x_xor_y.xor_assign(y); // x ⊕ y
        z_and_x_xor_y.and_assign(z); // z ∧ (x ⊕ y)

        // out = Maj(x, y, z) = xy ^ (z & (x ^ y))
        out.fast_zeroize();
        out.xor_assign(&xy);
        out.xor_assign(&z_and_x_xor_y);

        // Zeroize temporaries
        xy.fast_zeroize();
        z_and_x_xor_y.fast_zeroize();
    }

    /// Σ0(x) = ROTR^28(x) ^ ROTR^34(x) ^ ROTR^39(x)
    #[inline(always)]
    pub fn set_bsig0(out: &mut Word64, x: &Word64) {
        let mut v = Word64::new(x.get());

        out.fast_zeroize();

        // ROTR^28(x)
        v.rotate_right_assign(28);
        out.xor_assign(&v);
        v.rotate_left_assign(28); // restore x

        // ROTR^34(x)
        v.rotate_right_assign(34);
        out.xor_assign(&v);
        v.rotate_left_assign(34); // restore x

        // ROTR^39(x)
        v.rotate_right_assign(39);
        out.xor_assign(&v);

        v.fast_zeroize();
    }

    /// Σ1(x) = ROTR^14(x) ^ ROTR^18(x) ^ ROTR^41(x)
    #[inline(always)]
    pub fn set_bsig1(out: &mut Word64, x: &Word64) {
        let mut v = Word64::new(x.get());

        out.fast_zeroize();

        // ROTR^14(x)
        v.rotate_right_assign(14);
        out.xor_assign(&v);
        v.rotate_left_assign(14); // restore x

        // ROTR^18(x)
        v.rotate_right_assign(18);
        out.xor_assign(&v);
        v.rotate_left_assign(18); // restore x

        // ROTR^41(x)
        v.rotate_right_assign(41);
        out.xor_assign(&v);

        v.fast_zeroize();
    }

    /// σ0(x) = ROTR^1(x) ^ ROTR^8(x) ^ SHR^7(x)
    #[inline(always)]
    pub fn set_ssig0(out: &mut Word64, x: &Word64) {
        let mut v_rot = Word64::new(x.get());
        let mut v_shr = Word64::new(x.get());

        out.fast_zeroize();

        // ROTR^1(x)
        v_rot.rotate_right_assign(1);
        out.xor_assign(&v_rot);
        v_rot.rotate_left_assign(1); // restore x

        // ROTR^8(x)
        v_rot.rotate_right_assign(8);
        out.xor_assign(&v_rot);
        v_rot.fast_zeroize();

        // SHR^7(x)
        v_shr.shift_right_assign(7);
        out.xor_assign(&v_shr);
        v_shr.fast_zeroize();
    }

    /// σ1(x) = ROTR^19(x) ^ ROTR^61(x) ^ SHR^6(x)
    #[inline(always)]
    pub fn set_ssig1(out: &mut Word64, x: &Word64) {
        let mut v_rot = Word64::new(x.get());
        let mut v_shr = Word64::new(x.get());

        out.fast_zeroize();

        // ROTR^19(x)
        v_rot.rotate_right_assign(19);
        out.xor_assign(&v_rot);
        v_rot.rotate_left_assign(19); // restore x

        // ROTR^61(x)
        v_rot.rotate_right_assign(61);
        out.xor_assign(&v_rot);
        v_rot.fast_zeroize();

        // SHR^6(x)
        v_shr.shift_right_assign(6);
        out.xor_assign(&v_shr);
        v_shr.fast_zeroize();
    }
}

impl FastZeroizable for Word64 {
    fn fast_zeroize(&mut self) {
        self.0.fast_zeroize();
    }
}

impl ZeroizeMetadata for Word64 {
    const CAN_BE_BULK_ZEROIZED: bool = true;
}

impl ZeroizationProbe for Word64 {
    fn is_zeroized(&self) -> bool {
        self.0.is_zeroized()
    }
}

impl Drop for Word64 {
    fn drop(&mut self) {
        debug_assert!(self.is_zeroized());
        self.fast_zeroize();
    }
}
