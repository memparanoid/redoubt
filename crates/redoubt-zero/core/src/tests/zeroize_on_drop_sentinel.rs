// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::assert::assert_zeroize_on_drop;
use crate::traits::{AssertZeroizeOnDrop, FastZeroizable};
use crate::zeroize_on_drop_sentinel::ZeroizeOnDropSentinel;

#[test]
fn sentinel_functional_test() {
    struct Test {
        pub __sentinel: ZeroizeOnDropSentinel,
    }

    impl FastZeroizable for Test {
        fn fast_zeroize(&mut self) {
            self.__sentinel.fast_zeroize();
        }
    }

    impl Drop for Test {
        fn drop(&mut self) {
            self.fast_zeroize();
        }
    }

    impl AssertZeroizeOnDrop for Test {
        fn clone_sentinel(&self) -> ZeroizeOnDropSentinel {
            self.__sentinel.clone()
        }

        fn assert_zeroize_on_drop(self) {
            assert_zeroize_on_drop(self);
        }
    }

    let t = Test {
        __sentinel: ZeroizeOnDropSentinel::default(),
    };

    let sentinel_clone = t.clone_sentinel();

    assert_zeroize_on_drop(t);

    assert!(sentinel_clone.is_zeroized());
}

/// CRITICAL TEST: Verifies that zeroizing a ZeroizeOnDropSentinel also marks all clones as zeroized.
///
/// ZeroizeOnDropSentinel uses Arc<AtomicBool> internally so all clones share the same zeroization
/// state. When one instance is zeroized, ALL clones must reflect that state.
///
/// This is essential because we typically clone the sentinel before dropping the parent
/// struct, then check the clone's state to verify zeroization happened. If clones didn't
/// share state, this verification pattern would be impossible.
#[test]
fn test_sentinel_zeroizes_clone() {
    let mut sentinel = ZeroizeOnDropSentinel::default();
    let sentinel_clone = sentinel.clone();

    assert!(!sentinel.is_zeroized());
    assert!(!sentinel_clone.is_zeroized());
    sentinel.fast_zeroize();
    assert!(sentinel_clone.is_zeroized());
    assert!(sentinel_clone.is_zeroized());
}

/// CRITICAL TEST: Verifies that ZeroizeOnDropSentinel does NOT auto-zeroize when dropped.
///
/// This is the MOST IMPORTANT test for security correctness. ZeroizeOnDropSentinel must NOT
/// have a Drop impl that zeroizes itself, because that would create false positives.
///
/// If ZeroizeOnDropSentinel auto-zeroized on drop, every struct would appear "zeroized" even
/// without #[fast_zeroize(drop)], making the sentinel useless for security verification.
///
/// The sentinel should ONLY zeroize when the parent struct explicitly calls zeroize().
/// This test verifies that dropping a sentinel leaves it in the non-zeroized state.
#[test]
fn test_sentinel_is_not_zeroized_on_drop() {
    let sentinel = ZeroizeOnDropSentinel::default();
    let sentinel_clone = sentinel.clone();

    assert!(!sentinel_clone.is_zeroized());
    drop(sentinel);
    assert!(!sentinel_clone.is_zeroized());
}

#[test]
fn test_sentinel_partial_eq() {
    let mut sentinel1 = ZeroizeOnDropSentinel::default();
    let mut sentinel2 = ZeroizeOnDropSentinel::default();

    // Both pristine (not zeroized) - should be equal
    assert_eq!(sentinel1, sentinel2);

    // Zeroize first sentinel
    sentinel1.fast_zeroize();
    assert_ne!(sentinel1, sentinel2);

    // Zeroize second sentinel - now equal again
    sentinel2.fast_zeroize();
    assert_eq!(sentinel1, sentinel2);

    // Reset first sentinel - now different again
    sentinel1.reset();
    assert_ne!(sentinel1, sentinel2);

    // Reset second sentinel - equal again
    sentinel2.reset();
    assert_eq!(sentinel1, sentinel2);
}

#[test]
fn test_sentinel_fast_zeroize() {
    let mut sentinel = ZeroizeOnDropSentinel::default();
    let sentinel_clone = sentinel.clone();

    assert!(!sentinel.is_zeroized());
    assert!(!sentinel_clone.is_zeroized());

    // fast_zeroize() should mark as zeroized
    sentinel.fast_zeroize();

    assert!(sentinel.is_zeroized());
    assert!(sentinel_clone.is_zeroized());
}

#[test]
fn test_sentinel_reset() {
    let mut sentinel = ZeroizeOnDropSentinel::default();
    let sentinel_clone = sentinel.clone();

    // Zeroize
    sentinel.fast_zeroize();
    assert!(sentinel.is_zeroized());
    assert!(sentinel_clone.is_zeroized());

    // Reset to pristine state
    sentinel.reset();
    assert!(!sentinel.is_zeroized());
    assert!(!sentinel_clone.is_zeroized());

    // Can zeroize again
    sentinel.fast_zeroize();
    assert!(sentinel.is_zeroized());
    assert!(sentinel_clone.is_zeroized());
}
