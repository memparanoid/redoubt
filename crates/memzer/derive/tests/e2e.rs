// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer_core::{AssertZeroizeOnDrop, DropSentinel, ZeroizationProbe};
use memzer_derive::MemZer;
use zeroize::Zeroize;

fn main() {
    #[derive(Zeroize, MemZer)]
    #[zeroize(drop)]
    struct SensitiveData {
        pub data: Vec<u8>,
        __drop_sentinel: DropSentinel,
    }

    impl Default for SensitiveData {
        fn default() -> Self {
            Self {
                data: vec![1, 2, 3, 4],
                __drop_sentinel: DropSentinel::default(),
            }
        }
    }

    let mut sensitive_data = SensitiveData::default();

    // Assert (not) zeroization!
    assert!(!sensitive_data.is_zeroized());

    sensitive_data.zeroize();

    // Assert zeroization!
    assert!(sensitive_data.is_zeroized());

    sensitive_data.assert_zeroize_on_drop();
}
