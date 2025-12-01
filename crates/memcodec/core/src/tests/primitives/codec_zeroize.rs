// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::traits::CodecZeroize;

#[test]
fn test_codec_zeroize_is_noop() {
    let mut val: u64 = 12345;
    val.codec_zeroize();

    // codec_zeroize is a no-op for primitives - value unchanged
    // (collection handles zeroization via memset)
    assert_eq!(val, 12345);
}

#[test]
fn test_fast_zeroize_is_true() {
    assert!(bool::FAST_ZEROIZE);
    assert!(u8::FAST_ZEROIZE);
    assert!(u16::FAST_ZEROIZE);
    assert!(u32::FAST_ZEROIZE);
    assert!(u64::FAST_ZEROIZE);
    assert!(u128::FAST_ZEROIZE);
    assert!(usize::FAST_ZEROIZE);
    assert!(i8::FAST_ZEROIZE);
    assert!(i16::FAST_ZEROIZE);
    assert!(i32::FAST_ZEROIZE);
    assert!(i64::FAST_ZEROIZE);
    assert!(i128::FAST_ZEROIZE);
    assert!(isize::FAST_ZEROIZE);
    assert!(f32::FAST_ZEROIZE);
    assert!(f64::FAST_ZEROIZE);
}
