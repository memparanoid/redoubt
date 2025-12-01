// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::traits::{CodecZeroize, FastZeroize};

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
    assert!(<bool as FastZeroize>::FAST_ZEROIZE);
    assert!(<u8 as FastZeroize>::FAST_ZEROIZE);
    assert!(<u16 as FastZeroize>::FAST_ZEROIZE);
    assert!(<u32 as FastZeroize>::FAST_ZEROIZE);
    assert!(<u64 as FastZeroize>::FAST_ZEROIZE);
    assert!(<u128 as FastZeroize>::FAST_ZEROIZE);
    assert!(<usize as FastZeroize>::FAST_ZEROIZE);
    assert!(<i8 as FastZeroize>::FAST_ZEROIZE);
    assert!(<i16 as FastZeroize>::FAST_ZEROIZE);
    assert!(<i32 as FastZeroize>::FAST_ZEROIZE);
    assert!(<i64 as FastZeroize>::FAST_ZEROIZE);
    assert!(<i128 as FastZeroize>::FAST_ZEROIZE);
    assert!(<isize as FastZeroize>::FAST_ZEROIZE);
    assert!(<f32 as FastZeroize>::FAST_ZEROIZE);
    assert!(<f64 as FastZeroize>::FAST_ZEROIZE);
}
