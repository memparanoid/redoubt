// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::traits::AssertZeroizeOnDrop;

pub fn assert_zeroize_on_drop<T: AssertZeroizeOnDrop>(value: T) {
    let mut drop_sentinel = value.clone_drop_sentinel();

    drop_sentinel.reset();

    assert!(!drop_sentinel.is_dropped());
    drop(value);
    assert!(drop_sentinel.is_dropped());
}
