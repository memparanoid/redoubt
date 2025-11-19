// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer_core::{AssertZeroizeOnDrop, DropSentinel, Secret, ZeroizationProbe};
use memzer_derive::MemZer;
use zeroize::Zeroize;

fn main() {
    #[derive(Zeroize, MemZer)]
    #[zeroize(drop)]
    struct Foo {
        pub data: Secret<Vec<u8>>,
        __drop_sentinel: DropSentinel,
    }

    impl Default for Foo {
        fn default() -> Self {
            Self {
                data: Secret::from(vec![1, 2, 3, 4]),
                __drop_sentinel: DropSentinel::default(),
            }
        }
    }

    let mut foo = Foo::default();

    // Assert (not) zeroization!
    assert!(!foo.is_zeroized());

    foo.zeroize();

    // Assert zeroization!
    assert!(foo.is_zeroized());

    foo.assert_zeroize_on_drop();
}
