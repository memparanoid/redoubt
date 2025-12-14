// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::traits::PreAlloc;

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_zero_init_is_true() {
    assert!(u8::ZERO_INIT);
    assert!(u16::ZERO_INIT);
    assert!(u32::ZERO_INIT);
    assert!(u64::ZERO_INIT);
    assert!(u128::ZERO_INIT);
    assert!(usize::ZERO_INIT);
    assert!(i8::ZERO_INIT);
    assert!(i16::ZERO_INIT);
    assert!(i32::ZERO_INIT);
    assert!(i64::ZERO_INIT);
    assert!(i128::ZERO_INIT);
    assert!(isize::ZERO_INIT);
    assert!(f32::ZERO_INIT);
    assert!(f64::ZERO_INIT);
    assert!(bool::ZERO_INIT);
}

#[test]
fn test_prealloc_noop() {
    let mut val: u8 = 42;
    val.prealloc(999);
    assert_eq!(val, 42);
}
