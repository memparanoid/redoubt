// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::assert::assert_zeroize_on_drop;
use crate::drop_sentinel::DropSentinel;
use crate::traits::AssertZeroizeOnDrop;

#[test]
fn functional_test_for_drop_sentinel() {
    struct Test {
        pub __drop_sentinel: DropSentinel,
    }

    impl Zeroize for Test {
        fn zeroize(&mut self) {
            self.__drop_sentinel.zeroize();
        }
    }

    impl Drop for Test {
        fn drop(&mut self) {
            self.zeroize();
        }
    }

    impl AssertZeroizeOnDrop for Test {
        fn clone_drop_sentinel(&self) -> DropSentinel {
            self.__drop_sentinel.clone()
        }

        fn assert_zeroize_on_drop(self) {
            assert_zeroize_on_drop(self);
        }
    }

    let t = Test {
        __drop_sentinel: DropSentinel::default(),
    };

    let drop_sentinel_clone = t.clone_drop_sentinel();

    assert_zeroize_on_drop(t);

    assert!(drop_sentinel_clone.is_dropped());
}
