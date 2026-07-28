// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HkdfSha256State unit tests

use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::hkdf::HkdfSha256State;

// ╔════════════════════════════════════════════════════════════════════════════╗
// ║ ZEROIZATION                                                                ║
// ╚════════════════════════════════════════════════════════════════════════════╝

#[test]
fn test_hkdf_sha256_state_is_zeroizable() {
    let mut state = HkdfSha256State::new();

    state.unzeroize();
    assert!(!state.is_zeroized());

    state.fast_zeroize();
    assert!(state.is_zeroized());
}

#[test]
fn test_hkdf_sha256_state_zeroizes_on_drop() {
    let mut state = HkdfSha256State::new();

    state.unzeroize();
    assert!(!state.is_zeroized());

    state.assert_zeroize_on_drop();
}
