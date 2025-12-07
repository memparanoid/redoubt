// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::{FastZeroizable, ZeroizationProbe};

use crate::word::Word64;

const TEST_VALUES: [u64; 5] = [
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF,
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
    0x0F0F_0F0F_F0F0_F0F0,
];

#[test]
fn ch_matches_reference() {
    // Ch(x, y, z) = (x & y) ^ (!x & z)
    for &x in &TEST_VALUES {
        for &y in &TEST_VALUES {
            for &z in &TEST_VALUES {
                let mut out = Word64::zero();
                let mut wx = Word64::new(x);
                let mut wy = Word64::new(y);
                let mut wz = Word64::new(z);

                Word64::set_ch(&mut out, &wx, &wy, &wz);

                let expected = (x & y) ^ (!x & z);

                assert_eq!(
                    out.get(),
                    expected,
                    "Ch mismatch for x={x:#018x}, y={y:#018x}, z={z:#018x}"
                );

                // zeroize before drop to avoid debug_assert error
                out.fast_zeroize();
                wx.fast_zeroize();
                wy.fast_zeroize();
                wz.fast_zeroize();
            }
        }
    }
}

#[test]
fn maj_matches_reference() {
    // Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)
    for &x in &TEST_VALUES {
        for &y in &TEST_VALUES {
            for &z in &TEST_VALUES {
                let mut out = Word64::zero();
                let mut wx = Word64::new(x);
                let mut wy = Word64::new(y);
                let mut wz = Word64::new(z);

                Word64::set_maj(&mut out, &wx, &wy, &wz);

                let expected = (x & y) ^ (x & z) ^ (y & z);
                assert_eq!(
                    out.get(),
                    expected,
                    "Maj mismatch for x={x:#018x}, y={y:#018x}, z={z:#018x}"
                );

                // zeroize before drop to avoid debug_assert error
                out.fast_zeroize();
                wx.fast_zeroize();
                wy.fast_zeroize();
                wz.fast_zeroize();
            }
        }
    }
}

#[test]
fn bsig0_matches_reference() {
    // Σ0(x) = ROTR^28(x) ^ ROTR^34(x) ^ ROTR^39(x)
    for &x in &TEST_VALUES {
        let mut out = Word64::zero();
        let mut wx = Word64::new(x);

        Word64::set_bsig0(&mut out, &wx);

        let expected = x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39);
        assert_eq!(out.get(), expected, "BSIG0 mismatch for x={x:#018x}");

        // zeroize before drop to avoid debug_assert error
        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

#[test]
fn bsig1_matches_reference() {
    // Σ1(x) = ROTR^14(x) ^ ROTR^18(x) ^ ROTR^41(x)
    for &x in &TEST_VALUES {
        let mut out = Word64::zero();
        let mut wx = Word64::new(x);

        Word64::set_bsig1(&mut out, &wx);

        let expected = x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41);
        assert_eq!(out.get(), expected, "BSIG1 mismatch for x={x:#018x}");

        // zeroize before drop to avoid debug_assert error
        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

#[test]
fn ssig0_matches_reference() {
    // σ0(x) = ROTR^1(x) ^ ROTR^8(x) ^ SHR^7(x)
    for &x in &TEST_VALUES {
        let mut out = Word64::zero();
        let mut wx = Word64::new(x);

        Word64::set_ssig0(&mut out, &wx);

        let expected = x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7);
        assert_eq!(out.get(), expected, "SSIG0 mismatch for x={x:#018x}");

        // zeroize before drop to avoid debug_assert error
        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

#[test]
fn ssig1_matches_reference() {
    // σ1(x) = ROTR^19(x) ^ ROTR^61(x) ^ SHR^6(x)
    for &x in &TEST_VALUES {
        let mut out = Word64::zero();
        let mut wx = Word64::new(x);

        Word64::set_ssig1(&mut out, &wx);

        let expected = x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6);
        assert_eq!(out.get(), expected, "SSIG1 mismatch for x={x:#018x}");

        // zeroize before drop to avoid debug_assert error
        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

#[test]
fn word64_fast_zeroize_works() {
    // Basic sanity check for the zeroization contract.
    let mut w = Word64::new(0xDEAD_BEEF_DEAD_BEEF);
    assert!(!w.is_zeroized());
    w.fast_zeroize();
    assert!(w.is_zeroized());
}
