// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer_core::{AssertZeroizeOnDrop, DropSentinel, Secret, ZeroizationProbe};
use memzer_derive::MemZer;
use zeroize::Zeroize;

fn main() {
    #[derive(Zeroize, MemZer)]
    #[zeroize(drop)]
    struct TupleStruct(Secret<Vec<u8>>, Secret<[u8; 32]>, DropSentinel);

    impl Default for TupleStruct {
        fn default() -> Self {
            Self(
                Secret::from(&mut vec![1, 2, 3, 4]),
                Secret::from(&mut [u8::MAX; 32]),
                DropSentinel::default(),
            )
        }
    }

    let mut tuple_struct = TupleStruct::default();

    // Assert (not) zeroization!
    assert!(!tuple_struct.is_zeroized());

    tuple_struct.zeroize();

    // Assert zeroization!
    assert!(tuple_struct.is_zeroized());

    tuple_struct.assert_zeroize_on_drop();
}
