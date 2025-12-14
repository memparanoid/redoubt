// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Test helpers for verifying zeroization behavior.

use super::traits::AssertZeroizeOnDrop;

/// Asserts that a value zeroizes itself when dropped.
///
/// This function verifies that the [`ZeroizeOnDropSentinel`](crate::ZeroizeOnDropSentinel) of the given value
/// is marked as zeroized after the value is dropped.
///
/// # Panics
///
/// Panics if the value's `.zeroize()` method was not called during drop.
///
/// # How It Works
///
/// 1. Clones the value's [`ZeroizeOnDropSentinel`](crate::ZeroizeOnDropSentinel)
/// 2. Resets the sentinel to "not zeroized" state
/// 3. Drops the value
/// 4. Asserts the sentinel was marked as zeroized
///
/// Typically used in tests for types that implement [`AssertZeroizeOnDrop`].
pub fn assert_zeroize_on_drop<T: AssertZeroizeOnDrop>(value: T) {
    let mut sentinel = value.clone_sentinel();

    sentinel.reset();

    assert!(!sentinel.is_zeroized());
    drop(value);
    assert!(sentinel.is_zeroized());
}
