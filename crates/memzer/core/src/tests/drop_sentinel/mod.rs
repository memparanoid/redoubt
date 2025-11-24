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

/// CRITICAL TEST: Verifies that zeroizing a DropSentinel also marks all clones as zeroized.
///
/// DropSentinel uses Arc<AtomicBool> internally so all clones share the same zeroization
/// state. When one instance is zeroized, ALL clones must reflect that state.
///
/// This is essential because we typically clone the sentinel before dropping the parent
/// struct, then check the clone's state to verify zeroization happened. If clones didn't
/// share state, this verification pattern would be impossible.
#[test]
fn test_drop_sentinel_zeroizes_clone() {
    let mut drop_sentinel = DropSentinel::default();
    let drop_sentinel_clone = drop_sentinel.clone();

    assert!(!drop_sentinel.is_dropped());
    assert!(!drop_sentinel_clone.is_dropped());
    drop_sentinel.zeroize();
    assert!(drop_sentinel_clone.is_dropped());
    assert!(drop_sentinel_clone.is_dropped());
}

/// CRITICAL TEST: Verifies that DropSentinel does NOT auto-zeroize when dropped.
///
/// This is the MOST IMPORTANT test for security correctness. DropSentinel must NOT
/// have a Drop impl that zeroizes itself, because that would create false positives.
///
/// If DropSentinel auto-zeroized on drop, every struct would appear "zeroized" even
/// without #[zeroize(drop)], making the sentinel useless for security verification.
///
/// The sentinel should ONLY zeroize when the parent struct explicitly calls zeroize().
/// This test verifies that dropping a sentinel leaves it in the non-zeroized state.
#[test]
fn test_drop_sentinel_is_not_zeroized_on_drop() {
    let drop_sentinel = DropSentinel::default();
    let drop_sentinel_clone = drop_sentinel.clone();

    assert!(!drop_sentinel_clone.is_dropped());
    drop(drop_sentinel);
    assert!(!drop_sentinel_clone.is_dropped());
}
