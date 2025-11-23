// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
//! Test helpers for verifying zeroization behavior.

use super::traits::AssertZeroizeOnDrop;

/// Asserts that a value zeroizes itself when dropped.
///
/// This function verifies that the [`DropSentinel`](crate::DropSentinel) of the given value
/// is marked as zeroized after the value is dropped.
///
/// # Panics
///
/// Panics if the value's `.zeroize()` method was not called during drop.
///
/// # How It Works
///
/// 1. Clones the value's [`DropSentinel`](crate::DropSentinel)
/// 2. Resets the sentinel to "not zeroized" state
/// 3. Drops the value
/// 4. Asserts the sentinel was marked as zeroized
///
/// Typically used in tests for types that implement [`AssertZeroizeOnDrop`].
pub fn assert_zeroize_on_drop<T: AssertZeroizeOnDrop>(value: T) {
    let mut drop_sentinel = value.clone_drop_sentinel();

    drop_sentinel.reset();

    assert!(!drop_sentinel.is_dropped());
    drop(value);
    assert!(drop_sentinel.is_dropped());
}
