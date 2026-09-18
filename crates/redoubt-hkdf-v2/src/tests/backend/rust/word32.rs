// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The functions FIPS 180-4 defines over a word, and what a word leaves behind.
//!
//! # The oracle
//!
//! Each case computes the same answer a second time, in plain `u32` arithmetic
//! written from the standard's own formula. That is not the implementation
//! agreeing with itself: what is under test writes into storage the caller
//! named, a rotation at a time, with every temporary emptied before it returns,
//! and a single expression has none of that.
//!
//! The values are the extremes and patterns that disagree between neighbouring
//! bits, so a rotation off by one, or a shift where a rotation belongs, has
//! somewhere to show.

use redoubt_zero::{FastZeroizable, ZeroizationProbe};

use crate::backend::rust::word32::Word32;

const TEST_VALUES: [u32; 5] = [
    0x0000_0000,
    0xFFFF_FFFF,
    0x0123_4567,
    0xFEDC_BA98,
    0x0F0F_0F0F,
];

// ============================================================================
// Word32: FastZeroizable
// ============================================================================

/// Emptying a word that is holding something empties it.
#[test]
fn test_word32_is_zeroizable() {
    let mut word = Word32::new(0xDEAD_BEEF);

    assert!(!word.is_zeroized());

    word.fast_zeroize();

    assert!(word.is_zeroized());
}

// ============================================================================
// Word32::set_ch
// ============================================================================

/// `Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)`, FIPS 180-4 §4.1.2.
#[test]
fn test_set_ch_answers_what_the_standard_defines() {
    for &x in &TEST_VALUES {
        for &y in &TEST_VALUES {
            for &z in &TEST_VALUES {
                let mut out = Word32::zero();
                let mut wx = Word32::new(x);
                let mut wy = Word32::new(y);
                let mut wz = Word32::new(z);

                Word32::set_ch(&mut out, &wx, &wy, &wz);

                assert_eq!(
                    out.as_u32(),
                    (x & y) ^ (!x & z),
                    "x={x:#010x}, y={y:#010x}, z={z:#010x}"
                );

                out.fast_zeroize();
                wx.fast_zeroize();
                wy.fast_zeroize();
                wz.fast_zeroize();
            }
        }
    }
}

// ============================================================================
// Word32::set_maj
// ============================================================================

/// `Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)`, FIPS 180-4 §4.1.2.
///
/// The implementation takes the optimized form `(x ∧ y) ⊕ (z ∧ (x ⊕ y))`, and
/// what is asserted is the form the standard prints. They are equal by an
/// identity, which is exactly what a second formulation is for.
#[test]
fn test_set_maj_answers_what_the_standard_defines() {
    for &x in &TEST_VALUES {
        for &y in &TEST_VALUES {
            for &z in &TEST_VALUES {
                let mut out = Word32::zero();
                let mut wx = Word32::new(x);
                let mut wy = Word32::new(y);
                let mut wz = Word32::new(z);

                Word32::set_maj(&mut out, &wx, &wy, &wz);

                assert_eq!(
                    out.as_u32(),
                    (x & y) ^ (x & z) ^ (y & z),
                    "x={x:#010x}, y={y:#010x}, z={z:#010x}"
                );

                out.fast_zeroize();
                wx.fast_zeroize();
                wy.fast_zeroize();
                wz.fast_zeroize();
            }
        }
    }
}

// ============================================================================
// Word32::set_bsig0
// ============================================================================

/// `Σ0(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)`, FIPS 180-4 §4.1.2.
#[test]
fn test_set_bsig0_answers_what_the_standard_defines() {
    for &x in &TEST_VALUES {
        let mut out = Word32::zero();
        let mut wx = Word32::new(x);

        Word32::set_bsig0(&mut out, &wx);

        assert_eq!(
            out.as_u32(),
            x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22),
            "x={x:#010x}"
        );

        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

// ============================================================================
// Word32::set_bsig1
// ============================================================================

/// `Σ1(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)`, FIPS 180-4 §4.1.2.
#[test]
fn test_set_bsig1_answers_what_the_standard_defines() {
    for &x in &TEST_VALUES {
        let mut out = Word32::zero();
        let mut wx = Word32::new(x);

        Word32::set_bsig1(&mut out, &wx);

        assert_eq!(
            out.as_u32(),
            x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25),
            "x={x:#010x}"
        );

        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

// ============================================================================
// Word32::set_ssig0
// ============================================================================

/// `σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)`, FIPS 180-4 §4.1.2.
///
/// A shift and not a rotation in the last term: a rotation there would carry the
/// low bits back into the top, and every digest would still be a digest — of
/// something else.
#[test]
fn test_set_ssig0_answers_what_the_standard_defines() {
    for &x in &TEST_VALUES {
        let mut out = Word32::zero();
        let mut wx = Word32::new(x);

        Word32::set_ssig0(&mut out, &wx);

        assert_eq!(
            out.as_u32(),
            x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3),
            "x={x:#010x}"
        );

        out.fast_zeroize();
        wx.fast_zeroize();
    }
}

// ============================================================================
// Word32::set_ssig1
// ============================================================================

/// `σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)`, FIPS 180-4 §4.1.2.
#[test]
fn test_set_ssig1_answers_what_the_standard_defines() {
    for &x in &TEST_VALUES {
        let mut out = Word32::zero();
        let mut wx = Word32::new(x);

        Word32::set_ssig1(&mut out, &wx);

        assert_eq!(
            out.as_u32(),
            x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10),
            "x={x:#010x}"
        );

        out.fast_zeroize();
        wx.fast_zeroize();
    }
}
