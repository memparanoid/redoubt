// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.


use memzer_core::{AssertZeroizeOnDrop, ZeroizeOnDropSentinel, FastZeroizable, ZeroizationProbe};
use memzer_derive::MemZer;

fn main() {
    #[derive(MemZer)]
    struct SensitiveData {
        pub data: Vec<u8>,
        __sentinel: ZeroizeOnDropSentinel,
    }

    impl Drop for SensitiveData {
        fn drop(&mut self) {
            self.fast_zeroize();
        }
    }

    impl Default for SensitiveData {
        fn default() -> Self {
            Self {
                data: vec![1, 2, 3, 4],
                __sentinel: ZeroizeOnDropSentinel::default(),
            }
        }
    }

    let mut sensitive_data = SensitiveData::default();

    // Assert (not) zeroization!
    assert!(!sensitive_data.is_zeroized());

    sensitive_data.fast_zeroize();

    // Assert zeroization!
    assert!(sensitive_data.is_zeroized());

    sensitive_data.assert_zeroize_on_drop();
}
