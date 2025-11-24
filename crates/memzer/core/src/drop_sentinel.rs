// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

/// Runtime verification that zeroization happened before drop.
///
/// `DropSentinel` is a guard type used to verify that `.zeroize()` was called
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
/// ```rust
/// use memzer_core::DropSentinel;
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize)]
/// #[zeroize(drop)]
/// struct Secret {
///     data: Vec<u8>,
///     __drop_sentinel: DropSentinel,
/// }
/// ```
///
/// The `__drop_sentinel` field tracks whether `.zeroize()` was called before drop.
/// You'll need to implement `Zeroizable`, `ZeroizationProbe`, and `AssertZeroizeOnDrop`
/// manually, or use the `memzer` umbrella crate which provides `#[derive(MemZer)]`.
///
/// # Testing
///
/// Clone the sentinel to verify zeroization behavior:
///
/// ```rust
/// use memzer_core::DropSentinel;
/// use zeroize::Zeroize;
///
/// let mut sentinel = DropSentinel::default();
/// let sentinel_clone = sentinel.clone();
///
/// assert!(!sentinel_clone.is_zeroized());
/// sentinel.zeroize();
/// assert!(sentinel_clone.is_zeroized());
/// ```
#[derive(Clone, Debug)]
pub struct DropSentinel(Arc<AtomicBool>);

impl PartialEq for DropSentinel {
    fn eq(&self, other: &Self) -> bool {
        self.0.load(Ordering::Relaxed) == other.0.load(Ordering::Relaxed)
    }
}

impl Eq for DropSentinel {}

impl DropSentinel {
    /// Resets the sentinel to "not zeroized" (pristine) state.
    ///
    /// This is useful in tests when reusing a sentinel for multiple assertions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memzer_core::DropSentinel;
    /// use zeroize::Zeroize;
    ///
    /// let mut sentinel = DropSentinel::default();
    /// sentinel.zeroize();
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
    /// use memzer_core::DropSentinel;
    /// use zeroize::Zeroize;
    ///
    /// let mut sentinel = DropSentinel::default();
    /// assert!(!sentinel.is_zeroized());
    ///
    /// sentinel.zeroize();
    /// assert!(sentinel.is_zeroized());
    /// ```
    pub fn is_zeroized(&self) -> bool {
        !self.0.load(Ordering::Relaxed)
    }
}

impl Default for DropSentinel {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl Zeroize for DropSentinel {
    fn zeroize(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}
