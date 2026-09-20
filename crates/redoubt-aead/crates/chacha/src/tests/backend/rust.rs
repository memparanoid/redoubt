// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the Rust side holds, and that it is emptied.
//!
//! What each of these types holds in a build that ships is where its operations
//! go, and there is nothing there to empty. The marker the probe adds is what
//! the wipe and the drop work on here, so that they are exercised against
//! something rather than against a type that would pass either way.

use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::chacha20::ChaCha20;
use crate::hchacha20::HChaCha20;
use crate::xchacha20::XChaCha20;

// === === === === === === === === === ===
// ChaCha20
// === === === === === === === === === ===

#[test]
fn test_chacha20_is_zeroizable() {
    let mut chacha = ChaCha20::new();

    chacha.unzeroize();
    assert!(!chacha.is_zeroized());

    chacha.fast_zeroize();

    // Assert zeroization!
    assert!(chacha.is_zeroized());
}

#[test]
fn test_chacha20_zeroizes_on_drop() {
    let mut chacha = ChaCha20::new();

    chacha.unzeroize();
    assert!(!chacha.is_zeroized());

    // Assert zeroization!
    chacha.assert_zeroize_on_drop();
}

// === === === === === === === === === ===
// HChaCha20
// === === === === === === === === === ===

#[test]
fn test_hchacha20_is_zeroizable() {
    let mut hchacha = HChaCha20::new();

    hchacha.unzeroize();
    assert!(!hchacha.is_zeroized());

    hchacha.fast_zeroize();

    // Assert zeroization!
    assert!(hchacha.is_zeroized());
}

#[test]
fn test_hchacha20_zeroizes_on_drop() {
    let mut hchacha = HChaCha20::new();

    hchacha.unzeroize();
    assert!(!hchacha.is_zeroized());

    // Assert zeroization!
    hchacha.assert_zeroize_on_drop();
}

// === === === === === === === === === ===
// XChaCha20
// === === === === === === === === === ===

#[test]
fn test_xchacha20_is_zeroizable() {
    let mut xchacha = XChaCha20::new();

    xchacha.unzeroize();
    assert!(!xchacha.is_zeroized());

    xchacha.fast_zeroize();

    // Assert zeroization!
    assert!(xchacha.is_zeroized());
}

#[test]
fn test_xchacha20_zeroizes_on_drop() {
    let mut xchacha = XChaCha20::new();

    xchacha.unzeroize();
    assert!(!xchacha.is_zeroized());

    // Assert zeroization!
    xchacha.assert_zeroize_on_drop();
}
