// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! RAII guard for owned values that auto-zeroizes on drop.

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{Ordering, compiler_fence};

use crate::collections::{collection_zeroed, to_zeroization_probe_dyn_ref};

use super::assert::assert_zeroize_on_drop;
use super::zeroize_on_drop_sentinel::ZeroizeOnDropSentinel;
use super::traits::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

/// RAII guard for owned values that automatically zeroizes on drop.
///
/// `ZeroizingGuard` wraps an owned value `T` and ensures that it is zeroized
/// when the guard is dropped. This is useful for returning sensitive data from
/// functions while guaranteeing automatic cleanup.
///
/// # Design
///
/// - Wraps `T` (owns the value)
/// - Implements `Deref` and `DerefMut` for convenient access
/// - Zeroizes `inner` on drop
/// - Contains [`ZeroizeOnDropSentinel`] to verify zeroization happened
///
/// # Usage
///
/// ```rust
/// use redoubt_zero_core::{ZeroizingGuard, ZeroizationProbe};
///
/// fn create_sensitive_data() -> ZeroizingGuard<u64> {
///     ZeroizingGuard::new(12345)
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
    T: FastZeroizable + ZeroizationProbe,
{
    inner: T,
    __sentinel: ZeroizeOnDropSentinel,
}

impl<T> fmt::Debug for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED ZeroizingGuard]")
    }
}

impl<T> ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe,
{
    /// Creates a new guard wrapping an owned value.
    ///
    /// The guard takes ownership of the value and will zeroize it when dropped.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_zero_core::ZeroizingGuard;
    ///
    /// let guard = ZeroizingGuard::new(42u32);
    /// assert_eq!(*guard, 42);
    /// ```
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Consumes the guard and returns the inner value WITHOUT zeroizing it.
    ///
    /// # Safety
    ///
    /// This method bypasses the automatic zeroization. The caller is responsible
    /// for ensuring the value is properly zeroized when no longer needed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_zero_core::{ZeroizingGuard, FastZeroizable};
    ///
    /// let guard = ZeroizingGuard::new(42u32);
    /// let mut value = guard.into_inner();
    ///
    /// // Value is NOT zeroized yet - caller must do it manually
    /// value.fast_zeroize();
    /// ```
    pub fn into_inner(mut self) -> T {
        // Mark sentinel as zeroized to prevent panic on drop
        self.__sentinel.fast_zeroize();
        // Move out the inner value
        // SAFETY: We marked the sentinel as zeroized, so Drop won't panic.
        // The caller is now responsible for zeroizing the value.
        unsafe { core::ptr::read(&self.inner) }
    }
}

impl<T> Deref for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> FastZeroizable for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe,
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
    T: FastZeroizable + ZeroizationProbe,
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
    T: FastZeroizable + ZeroizationProbe,
{
    fn is_zeroized(&self) -> bool {
        let fields: [&dyn ZeroizationProbe; 1] = [to_zeroization_probe_dyn_ref(&self.inner)];
        collection_zeroed(&mut fields.into_iter())
    }
}

impl<T> Drop for ZeroizingGuard<T>
where
    T: FastZeroizable + ZeroizationProbe,
{
    fn drop(&mut self) {
        self.fast_zeroize();
    }
}
