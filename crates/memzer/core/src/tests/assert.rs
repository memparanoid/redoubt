// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::assert::assert_zeroize_on_drop;
use crate::traits::{AssertZeroizeOnDrop, FastZeroizable};
use crate::zeroize_on_drop_sentinel::ZeroizeOnDropSentinel;
use crate::zeroizing_mut_guard::ZeroizingMutGuard;

/// CRITICAL TEST: Verifies that structs WITH #[zeroize(drop)] properly zeroize on drop.
///
/// This test ensures that when a struct has #[zeroize(drop)], the ZeroizeOnDropSentinel correctly
/// detects zeroization. This is essential for security because it confirms that sensitive
/// data is being cleared from memory when structs are dropped, even in panic scenarios.
///
/// Without this verification, memory might contain sensitive data after drop, creating
/// security vulnerabilities.
#[test]
fn test_assert_zeroized_on_drop_ok() {
    struct StructThatIsZeroizedOnDrop<'a> {
        data: ZeroizingMutGuard<'a, [u8; 32]>,
        __sentinel: ZeroizeOnDropSentinel,
    }

    impl<'a> FastZeroizable for StructThatIsZeroizedOnDrop<'a> {
        fn fast_zeroize(&mut self) {
            self.data.fast_zeroize();
            self.__sentinel.fast_zeroize();
        }
    }

    impl<'a> StructThatIsZeroizedOnDrop<'a> {
        fn new(data: &'a mut [u8; 32]) -> Self {
            Self {
                data: ZeroizingMutGuard::from(data),
                __sentinel: ZeroizeOnDropSentinel::default(),
            }
        }
    }

    impl<'a> AssertZeroizeOnDrop for StructThatIsZeroizedOnDrop<'a> {
        fn clone_sentinel(&self) -> ZeroizeOnDropSentinel {
            self.__sentinel.clone()
        }

        fn assert_zeroize_on_drop(self) {
            assert_zeroize_on_drop(self);
        }
    }

    impl<'a> Drop for StructThatIsZeroizedOnDrop<'a> {
        fn drop(&mut self) {
            self.fast_zeroize();
        }
    }

    let mut data = [1u8; 32];

    {
        let s = StructThatIsZeroizedOnDrop::new(&mut data);
        s.assert_zeroize_on_drop();
    }

    // Assert zeroization!
    assert!(data.iter().all(|b| *b == 0));
}

/// CRITICAL TEST: Verifies that structs WITHOUT #[zeroize(drop)] are detected and panic.
///
/// This test is ESSENTIAL for security. It ensures that ZeroizeOnDropSentinel correctly identifies
/// when a struct is NOT being zeroized on drop (missing #[zeroize(drop)] attribute).
///
/// ZeroizeOnDropSentinel must ONLY zeroize when explicitly told to (via parent's zeroize()).
/// If it auto-zeroized itself, it would create FALSE POSITIVES - reporting structs as
/// "zeroized" even when they weren't. This would be a SILENT SECURITY BUG that could
/// leave sensitive data in memory.
///
/// This test verifies the sentinel correctly panics when zeroization doesn't happen,
/// preventing false security guarantees.
#[test]
fn test_assert_zeroized_on_drop_failure() {
    use std::panic::catch_unwind;

    struct StructThatIsNotZeroizedOnDrop<'a> {
        data: ZeroizingMutGuard<'a, [u8; 32]>,
        __sentinel: ZeroizeOnDropSentinel,
    }

    impl<'a> FastZeroizable for StructThatIsNotZeroizedOnDrop<'a> {
        fn fast_zeroize(&mut self) {
            self.data.fast_zeroize();
            self.__sentinel.fast_zeroize();
        }
    }

    impl<'a> StructThatIsNotZeroizedOnDrop<'a> {
        fn new(data: &'a mut [u8; 32]) -> Self {
            Self {
                data: ZeroizingMutGuard::from(data),
                __sentinel: ZeroizeOnDropSentinel::default(),
            }
        }
    }

    impl<'a> AssertZeroizeOnDrop for StructThatIsNotZeroizedOnDrop<'a> {
        fn clone_sentinel(&self) -> ZeroizeOnDropSentinel {
            self.__sentinel.clone()
        }

        fn assert_zeroize_on_drop(self) {
            assert_zeroize_on_drop(self);
        }
    }

    let mut data = [1u8; 32];

    let result = catch_unwind(move || {
        let s = StructThatIsNotZeroizedOnDrop::new(&mut data);
        s.assert_zeroize_on_drop();
    });

    assert!(result.is_err());

    // Assert (not) zeroization!
    assert!(data.iter().all(|b| *b == 1));
}
