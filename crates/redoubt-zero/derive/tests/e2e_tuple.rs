// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero_core::{
    AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe, ZeroizeOnDropSentinel,
};
use redoubt_zero_derive::RedoubtZero;

fn main() {
    #[derive(RedoubtZero)]
    struct TupleStruct(Vec<u8>, [u8; 32], ZeroizeOnDropSentinel);

    impl Drop for TupleStruct {
        fn drop(&mut self) {
            self.fast_zeroize();
        }
    }

    impl Default for TupleStruct {
        fn default() -> Self {
            Self(
                vec![1, 2, 3, 4],
                [u8::MAX; 32],
                ZeroizeOnDropSentinel::default(),
            )
        }
    }

    let mut tuple_struct = TupleStruct::default();

    // Assert (not) zeroization!
    assert!(!tuple_struct.is_zeroized());

    tuple_struct.fast_zeroize();

    // Assert zeroization!
    assert!(tuple_struct.is_zeroized());

    tuple_struct.assert_zeroize_on_drop();
}
