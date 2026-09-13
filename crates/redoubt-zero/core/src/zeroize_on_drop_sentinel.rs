// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

extern crate alloc;

use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{FastZeroizable, ZeroizeMetadata};

/// A flag that records whether zeroization happened, so a test can ask.
///
/// # It records; it does not enforce
///
/// This type has no `Drop` of its own and nothing here panics. All it is, is
/// one shared boolean: `true` while the value is pristine, `false` once
/// something called `.zeroize()` on it.
///
/// What turns that into an assertion is [`crate::assert_zeroize_on_drop`],
/// which a test calls deliberately — it clones the flag, drops the value, and
/// checks that the drop flipped it. Nothing does this on its own, and a type
/// that forgets to zeroize goes unnoticed unless a test asks.
///
/// An earlier version of this documentation said the opposite: that it
/// "panics on drop if `.zeroize()` was not called". It never did, and a
/// caller reading that would have believed a guarantee that was not there.
///
/// # It is not free
///
/// It is an `Arc<AtomicBool>`, so every value holding one costs a heap
/// allocation and an atomic. In a crate whose reason for existing is to leave
/// nothing in memory, that allocation is not a rounding error: the allocator's
/// own wide copies are exactly the kind of thing a secret gets left in.
///
/// So the types in this workspace carry the field only under `cfg(test)`, and
/// the `RedoubtZero` derive treats it as optional for that reason.
///
/// # Design
///
/// - Wraps a shared boolean flag (`Arc<AtomicBool>`) representing pristine state
/// - Initially `true` (pristine/untouched)
/// - `.zeroize()` sets the flag to `false` (no longer pristine)
/// - Cloned, so a test can hold the flag after the value it belonged to is gone
///
/// # Usage
///
/// Typically used as a field in structs to verify zeroization:
///
/// ```rust,ignore
/// use redoubt_zero_core::{ZeroizeOnDropSentinel, FastZeroizable};
///
/// struct Secret {
///     data: Vec<u8>,
///     #[cfg(test)]
///     __sentinel: ZeroizeOnDropSentinel,
/// }
///
/// impl Drop for Secret {
///     fn drop(&mut self) {
///         self.data.fast_zeroize();
///
///         // The flag is only marked where it exists; the wipe above is what
///         // matters and happens either way.
///         #[cfg(test)]
///         self.__sentinel.fast_zeroize();
///     }
/// }
/// ```
///
/// The `__sentinel` field tracks whether `.zeroize()` was called before drop.
/// You'll need to implement `FastZeroizable`, `ZeroizationProbe`, and `AssertZeroizeOnDrop`
/// manually, or use the `RedoubtZero` umbrella crate which provides `#[derive(RedoubtZero)]`.
///
/// # Testing
///
/// Clone the sentinel to verify zeroization behavior:
///
/// ```rust
/// use redoubt_zero_core::ZeroizeOnDropSentinel;
/// use redoubt_zero_core::FastZeroizable;
///
/// let mut sentinel = ZeroizeOnDropSentinel::default();
/// let sentinel_clone = sentinel.clone();
///
/// assert!(!sentinel_clone.is_zeroized());
/// sentinel.fast_zeroize();
/// assert!(sentinel_clone.is_zeroized());
/// ```
#[derive(Clone, Debug)]
pub struct ZeroizeOnDropSentinel(Arc<AtomicBool>);

impl PartialEq for ZeroizeOnDropSentinel {
    fn eq(&self, other: &Self) -> bool {
        self.0.load(Ordering::Relaxed) == other.0.load(Ordering::Relaxed)
    }
}

impl Eq for ZeroizeOnDropSentinel {}

impl ZeroizeOnDropSentinel {
    /// Resets the sentinel to "not zeroized" (pristine) state.
    ///
    /// This is useful in tests when reusing a sentinel for multiple assertions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_zero_core::{ZeroizeOnDropSentinel, FastZeroizable, ZeroizationProbe};
    ///
    /// let mut sentinel = ZeroizeOnDropSentinel::default();
    /// sentinel.fast_zeroize();
    /// assert!(sentinel.is_zeroized());
    ///
    /// sentinel.reset();
    /// assert!(!sentinel.is_zeroized());
    /// ```
    pub fn reset(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Checks if zeroization happened (i.e., if `.zeroize()` was called).
    ///
    /// Returns `true` if the sentinel was zeroized, `false` if still pristine.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_zero_core::{ZeroizeOnDropSentinel, FastZeroizable, ZeroizationProbe};
    ///
    /// let mut sentinel = ZeroizeOnDropSentinel::default();
    /// assert!(!sentinel.is_zeroized());
    ///
    /// sentinel.fast_zeroize();
    /// assert!(sentinel.is_zeroized());
    /// ```
    pub fn is_zeroized(&self) -> bool {
        !self.0.load(Ordering::Relaxed)
    }
}

impl Default for ZeroizeOnDropSentinel {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl ZeroizeMetadata for ZeroizeOnDropSentinel {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for ZeroizeOnDropSentinel {
    fn fast_zeroize(&mut self) {
        // SAFETY: Using volatile write to prevent compiler from optimizing away the store
        unsafe {
            ptr::write_volatile(&mut *self.0.as_ptr(), false);
        }
    }
}
