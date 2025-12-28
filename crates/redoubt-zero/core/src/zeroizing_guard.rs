// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! RAII guard for owned values that auto-zeroizes on drop.

use alloc::boxed::Box;
use core::fmt;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{Ordering, compiler_fence};

use crate::collections::{collection_zeroed, to_zeroization_probe_dyn_ref};

use super::assert::assert_zeroize_on_drop;
use super::traits::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};
use super::zeroize_on_drop_sentinel::ZeroizeOnDropSentinel;

/// RAII guard for owned values that automatically zeroizes on drop.
///
/// `ZeroizingGuard` wraps an owned value `T` in a `Box` and ensures that it is zeroized
/// when the guard is dropped. This is useful for returning sensitive data from
/// functions while guaranteeing automatic cleanup.
///
/// # Design
///
/// - Wraps `Box<T>` (owns the value on the heap, avoiding stack copies)
/// - Takes `&mut T` in constructor and swaps with `T::default()`, zeroizing the source
/// - Implements `Deref` and `DerefMut` for convenient access
/// - Zeroizes `inner` on drop
/// - Contains [`ZeroizeOnDropSentinel`] to verify zeroization happened
///
/// # Usage
///
/// ```rust
/// use redoubt_zero_core::{ZeroizingGuard, ZeroizationProbe, FastZeroizable};
///
/// fn create_sensitive_data() -> ZeroizingGuard<u64> {
///     let mut value = 12345u64;
///     ZeroizingGuard::from_mut(&mut value)
/// }
///
/// {
///     let guard = create_sensitive_data();
///     assert_eq!(*guard, 12345);
/// } // guard drops here → value is zeroized
/// ```
///
/// # Panics
///
/// The guard panics on drop if the wrapped value's [`ZeroizeOnDropSentinel`] was not
/// marked as zeroized. This ensures zeroization invariants are enforced.
pub struct ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe + Default,
{
    inner: Box<T>,
    __sentinel: ZeroizeOnDropSentinel,
}

impl<T> fmt::Debug for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe + Default,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED ZeroizingGuard]")
    }
}

impl<T> ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe + Default,
{
    /// Creates a new guard by swapping the value from the source and zeroizing it.
    ///
    /// The source location is swapped with `T::default()` and then zeroized,
    /// ensuring no copies of the sensitive data remain on the stack.
    /// The value is stored in a `Box` on the heap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_zero_core::{ZeroizingGuard, ZeroizationProbe};
    ///
    /// let mut value = 42u32;
    /// let guard = ZeroizingGuard::from_mut(&mut value);
    /// assert_eq!(*guard, 42);
    /// assert!(value.is_zeroized()); // source is zeroized
    /// ```
    pub fn from_mut(value: &mut T) -> Self {
        // Allocate box with default value
        let mut boxed = Box::new(T::default());
        // Swap value into the box
        mem::swap(&mut *boxed, value);
        // Zeroize the source location
        value.fast_zeroize();

        Self {
            inner: boxed,
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Creates a new guard with the default value of `T`.
    ///
    /// This is a convenience method equivalent to:
    /// ```rust,ignore
    /// let mut value = T::default();
    /// ZeroizingGuard::from_mut(&mut value)
    /// ```
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_zero_core::{ZeroizingGuard, ZeroizationProbe};
    ///
    /// let guard: ZeroizingGuard<u64> = ZeroizingGuard::from_default();
    /// assert!(guard.is_zeroized());
    /// ```
    #[inline(always)]
    pub fn from_default() -> Self {
        let mut value = T::default();
        Self::from_mut(&mut value)
    }
}

impl<T> Deref for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe + Default,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe + Default,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> FastZeroizable for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe + Default,
{
    fn fast_zeroize(&mut self) {
        self.inner.fast_zeroize();
        compiler_fence(Ordering::SeqCst);

        self.__sentinel.fast_zeroize();
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T> AssertZeroizeOnDrop for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe + Default,
{
    fn clone_sentinel(&self) -> ZeroizeOnDropSentinel {
        self.__sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

impl<T> ZeroizationProbe for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe + Default,
{
    fn is_zeroized(&self) -> bool {
        let fields: [&dyn ZeroizationProbe; 1] = [to_zeroization_probe_dyn_ref(&*self.inner)];
        collection_zeroed(&mut fields.into_iter())
    }
}

impl<T> Drop for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe + Default,
{
    fn drop(&mut self) {
        self.fast_zeroize();
    }
}
