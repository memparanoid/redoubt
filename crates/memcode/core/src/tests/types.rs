// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::traits::*;
use crate::types::*;

#[test]
fn test_default_zero_values() {
    let a = MemCodeWord::default_zero_value();
    let b = MemCodeUnit::default_zero_value();

    assert_eq!(a, 0);
    assert_eq!(b, 0);
}

#[test]
fn test_cast() {
    let a = MemCodeWord::cast(20);
    let b = MemCodeUnit::cast(20);

    assert_eq!(a, 20);
    assert_eq!(b, 20);
}
