// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! RAII guard for mutable references that auto-zeroizes on drop.

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{Ordering, compiler_fence};

use super::assert::assert_zeroize_on_drop;
use super::drop_sentinel::DropSentinel;
use super::traits::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

/// RAII guard for mutable references that automatically zeroizes on drop.
///
/// `ZeroizingMutGuard` wraps a mutable reference `&mut T` and ensures that
/// the referenced value is zeroized when the guard is dropped. This is useful
/// for protecting sensitive data during temporary operations (e.g., encryption,
/// decryption, signing).
///
/// # Design
///
/// - Wraps `&'a mut T` (borrows the value mutably)
/// - Implements `Deref` and `DerefMut` for convenient access
/// - Zeroizes `*inner` on drop via `#[zeroize(drop)]`
/// - Contains [`DropSentinel`] to verify zeroization happened
///
/// # Usage
///
/// ```rust
/// use memzer_core::{ZeroizingMutGuard, ZeroizationProbe};
///
/// let mut sensitive: u64 = 12345;
///
/// {
///     // Guard borrows `sensitive` and zeroizes it on drop
///     let mut guard = ZeroizingMutGuard::from(&mut sensitive);
///     *guard = 67890;
///     println!("Value: {}", *guard);
/// } // guard drops here → sensitive is zeroized
///
/// assert!(sensitive.is_zeroized());
/// ```
///
/// # Composition with Crypto Operations
///
/// `ZeroizingMutGuard` is heavily used in `memcrypt` for wrapping keys and nonces:
///
/// ```rust,ignore
/// use memzer_core::ZeroizingMutGuard;
/// use memcrypt::{AeadKey, XNonce};
///
/// struct EncryptionContext<'a> {
///     key: ZeroizingMutGuard<'a, AeadKey>,
///     nonce: ZeroizingMutGuard<'a, XNonce>,
/// }
///
/// impl Drop for EncryptionContext<'_> {
///     fn drop(&mut self) {
///         // key and nonce auto-zeroize when guards drop
///     }
/// }
/// ```
///
/// # Panics
///
/// The guard panics on drop if the wrapped value's [`DropSentinel`] was not
/// marked as zeroized. This ensures zeroization invariants are enforced.
pub struct ZeroizingMutGuard<'a, T>
where
    T: FastZeroizable + ZeroizationProbe + ?Sized,
{
    inner: &'a mut T,
    __drop_sentinel: DropSentinel,
}

impl<'a, T> fmt::Debug for ZeroizingMutGuard<'a, T>
where
    T: FastZeroizable + ZeroizationProbe + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED ZeroizingMutGuard]")
    }
}

impl<'a, T> ZeroizingMutGuard<'a, T>
where
    T: FastZeroizable + ZeroizationProbe + ?Sized,
{
    /// Creates a new guard wrapping a mutable reference.
    ///
    /// The guard takes ownership of the mutable reference and will zeroize
    /// the referenced value when dropped.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memzer_core::ZeroizingMutGuard;
    ///
    /// let mut value: u32 = 42;
    ///
    /// let guard = ZeroizingMutGuard::from(&mut value);
    /// assert_eq!(*guard, 42);
    /// ```
    pub fn from(inner: &'a mut T) -> Self {
        Self {
            inner,
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl<'a, T> Deref for ZeroizingMutGuard<'a, T>
where
    T: FastZeroizable + ZeroizationProbe + ?Sized,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'a, T> DerefMut for ZeroizingMutGuard<'a, T>
where
    T: FastZeroizable + ZeroizationProbe + ?Sized,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
    }
}

impl<'a, T> FastZeroizable for ZeroizingMutGuard<'a, T>
where
    T: FastZeroizable + ZeroizationProbe + ?Sized,
{
    fn fast_zeroize(&mut self) {
        self.inner.fast_zeroize();
        compiler_fence(Ordering::SeqCst);

        self.__drop_sentinel.fast_zeroize();
        compiler_fence(Ordering::SeqCst);
    }
}

impl<'a, T> AssertZeroizeOnDrop for ZeroizingMutGuard<'a, T>
where
    T: FastZeroizable + ZeroizationProbe + ?Sized,
{
    fn clone_drop_sentinel(&self) -> crate::drop_sentinel::DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

impl<'a, T> ZeroizationProbe for ZeroizingMutGuard<'a, T>
where
    T: FastZeroizable + ZeroizationProbe + ?Sized,
{
    fn is_zeroized(&self) -> bool {
        self.inner.is_zeroized()
    }
}

impl<'a, T> Drop for ZeroizingMutGuard<'a, T>
where
    T: FastZeroizable + ZeroizationProbe + ?Sized,
{
    fn drop(&mut self) {
        self.fast_zeroize();
    }
}
