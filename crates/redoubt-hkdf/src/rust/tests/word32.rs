// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::{FastZeroizable, ZeroizationProbe};

use crate::rust::word32::Word32;

const TEST_VALUES: [u32; 5] = [
    0x0000_0000,
    0xFFFF_FFFF,
    0x0123_4567,
    0xFEDC_BA98,
    0x0F0F_0F0F,
];

#[test]
fn ch_matches_reference() {
    // Ch(x, y, z) = (x & y) ^ (!x & z)
    for &x in &TEST_VALUES {
        for &y in &TEST_VALUES {
            for &z in &TEST_VALUES {
                let mut out = Word32::zero();
                let mut wx = Word32::new(x);
                let mut wy = Word32::new(y);
                let mut wz = Word32::new(z);

                Word32::set_ch(&mut out, &wx, &wy, &wz);

                let expected = (x & y) ^ (!x & z);

                assert_eq!(
                    out.as_u32(),
                    expected,
                    "Ch mismatch for x={x:#010x}, y={y:#010x}, z={z:#010x}"
                );

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
                let mut out = Word32::zero();
                let mut wx = Word32::new(x);
                let mut wy = Word32::new(y);
                let mut wz = Word32::new(z);

                Word32::set_maj(&mut out, &wx, &wy, &wz);

                let expected = (x & y) ^ (x & z) ^ (y & z);
                assert_eq!(
                    out.as_u32(),
                    expected,
                    "Maj mismatch for x={x:#010x}, y={y:#010x}, z={z:#010x}"
                );

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
    // Σ0(x) = ROTR^2(x) ^ ROTR^13(x) ^ ROTR^22(x)
    for &x in &TEST_VALUES {
        let mut out = Word32::zero();
        let mut wx = Word32::new(x);

        Word32::set_bsig0(&mut out, &wx);

        let expected = x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22);
        assert_eq!(out.as_u32(), expected, "BSIG0 mismatch for x={x:#010x}");

        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

#[test]
fn bsig1_matches_reference() {
    // Σ1(x) = ROTR^6(x) ^ ROTR^11(x) ^ ROTR^25(x)
    for &x in &TEST_VALUES {
        let mut out = Word32::zero();
        let mut wx = Word32::new(x);

        Word32::set_bsig1(&mut out, &wx);

        let expected = x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25);
        assert_eq!(out.as_u32(), expected, "BSIG1 mismatch for x={x:#010x}");

        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

#[test]
fn ssig0_matches_reference() {
    // σ0(x) = ROTR^7(x) ^ ROTR^18(x) ^ SHR^3(x)
    for &x in &TEST_VALUES {
        let mut out = Word32::zero();
        let mut wx = Word32::new(x);

        Word32::set_ssig0(&mut out, &wx);

        let expected = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
        assert_eq!(out.as_u32(), expected, "SSIG0 mismatch for x={x:#010x}");

        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

#[test]
fn ssig1_matches_reference() {
    // σ1(x) = ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)
    for &x in &TEST_VALUES {
        let mut out = Word32::zero();
        let mut wx = Word32::new(x);

        Word32::set_ssig1(&mut out, &wx);

        let expected = x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10);
        assert_eq!(out.as_u32(), expected, "SSIG1 mismatch for x={x:#010x}");

        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

#[test]
fn word32_fast_zeroize_works() {
    let mut w = Word32::new(0xDEAD_BEEF);
    assert!(!w.is_zeroized());
    w.fast_zeroize();
    assert!(w.is_zeroized());
}
