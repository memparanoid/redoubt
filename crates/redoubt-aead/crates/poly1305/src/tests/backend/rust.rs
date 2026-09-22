// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the Rust side holds, and that none of it comes back out.

use redoubt_aead_core::consts::poly1305::KEY_SIZE;
use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::poly1305::Poly1305;

#[test]
fn test_poly1305_is_zeroizable() {
    let mut poly = Poly1305::new();

    poly.init(&[0x11; KEY_SIZE]);
    poly.unzeroize();
    assert!(!poly.is_zeroized());

    poly.fast_zeroize();

    // Assert zeroization!
    assert!(poly.is_zeroized());
}

#[test]
fn test_poly1305_zeroizes_on_drop() {
    let mut poly = Poly1305::new();

    poly.init(&[0x11; KEY_SIZE]);
    poly.unzeroize();
    assert!(!poly.is_zeroized());

    // Assert zeroization!
    poly.assert_zeroize_on_drop();
}

#[test]
fn test_poly1305_debug_says_nothing() {
    let mut poly = Poly1305::new();

    poly.init(&[0xab; KEY_SIZE]);

    assert_eq!(std::format!("{poly:?}"), "Poly1305 { [protected] }");
}
