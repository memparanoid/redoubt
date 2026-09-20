// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What an `HmacSha256State` leaves behind.

use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::backend::rust::hmac::HmacSha256State;

// ============================================================================
// HmacSha256State
// ============================================================================

/// Emptying a state that is holding something empties it.
///
/// The dirtying is the half that makes the answer worth anything: a probe that
/// reached nowhere would report a clean state, and so would a clean one.
#[test]
fn test_hmac_sha256_state_is_zeroizable() {
    let mut state = HmacSha256State::new();

    state.unzeroize();
    assert!(!state.is_zeroized());

    state.fast_zeroize();
    assert!(state.is_zeroized());
}

/// A state that goes out of scope holding something empties itself.
#[test]
fn test_hmac_sha256_state_zeroizes_on_drop() {
    let mut state = HmacSha256State::new();

    state.unzeroize();
    assert!(!state.is_zeroized());

    state.assert_zeroize_on_drop();
}
