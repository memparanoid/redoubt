// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
extern crate alloc;

use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{FastZeroizable, ZeroizeMetadata};

/// Runtime verification that zeroization happened before drop.
///
/// `ZeroizeOnDropSentinel` is a guard type used to verify that `.zeroize()` was called
/// before a value is dropped. This provides **runtime enforcement** of zeroization
/// invariants, complementing compile-time checks.
///
/// # Design
///
/// - Wraps a shared boolean flag (`Arc<AtomicBool>`) representing pristine state
/// - Initially `true` (pristine/untouched)
/// - `.zeroize()` sets the flag to `false` (no longer pristine)
/// - Can be cloned to verify zeroization from tests
///
/// # Panics
///
/// Panics on drop if `.zeroize()` was not called before drop. This is intentional:
/// forgetting to zeroize sensitive data is a critical bug that must be caught.
///
/// # Usage
///
/// Typically used as a field in structs to verify zeroization:
///
/// ```rust,ignore
/// use memzer_core::{ZeroizeOnDropSentinel, FastZeroizable};
///
/// struct Secret {
///     data: Vec<u8>,
///     __sentinel: ZeroizeOnDropSentinel,
/// }
///
/// impl Drop for Secret {
///     fn drop(&mut self) {
///         self.data.fast_zeroize();
///         self.__sentinel.fast_zeroize();
///     }
/// }
/// ```
///
/// The `__sentinel` field tracks whether `.zeroize()` was called before drop.
/// You'll need to implement `FastZeroizable`, `ZeroizationProbe`, and `AssertZeroizeOnDrop`
/// manually, or use the `memzer` umbrella crate which provides `#[derive(MemZer)]`.
///
/// # Testing
///
/// Clone the sentinel to verify zeroization behavior:
///
/// ```rust
/// use memzer_core::ZeroizeOnDropSentinel;
/// use memzer_core::FastZeroizable;
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
    /// use memzer_core::{ZeroizeOnDropSentinel, FastZeroizable, ZeroizationProbe};
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
    /// use memzer_core::{ZeroizeOnDropSentinel, FastZeroizable, ZeroizationProbe};
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
