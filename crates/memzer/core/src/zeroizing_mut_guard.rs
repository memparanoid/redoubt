// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! RAII guard for mutable references that auto-zeroizes on drop.

use core::fmt;
use core::ops::{Deref, DerefMut};

use zeroize::Zeroize;

use crate::collections::{
    collection_zeroed, to_fast_zeroizable_dyn_mut, to_zeroization_probe_dyn_ref, zeroize_collection,
};

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
/// use memzer_core::{ZeroizingMutGuard, ZeroizationProbe, primitives::U64};
///
/// let mut sensitive = U64::default();
/// *sensitive.expose_mut() = 0xdeadbeef;
///
/// {
///     // Guard borrows `sensitive` and zeroizes it on drop
///     let mut guard = ZeroizingMutGuard::from(&mut sensitive);
///     *guard.expose_mut() = 0xcafebabe;
///     println!("Value: {}", guard.expose());
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
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ZeroizingMutGuard<'a, T>
where
    T: Zeroize + FastZeroizable + ZeroizationProbe,
{
    inner: &'a mut T,
    __drop_sentinel: DropSentinel,
}

impl<'a, T> fmt::Debug for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + FastZeroizable + ZeroizationProbe,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED ZeroizingMutGuard]")
    }
}

impl<'a, T> ZeroizingMutGuard<'a, T>
where
    T: Zeroize + FastZeroizable + ZeroizationProbe,
{
    /// Creates a new guard wrapping a mutable reference.
    ///
    /// The guard takes ownership of the mutable reference and will zeroize
    /// the referenced value when dropped.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memzer_core::{ZeroizingMutGuard, primitives::U32};
    ///
    /// let mut value = U32::default();
    /// *value.expose_mut() = 42;
    ///
    /// let guard = ZeroizingMutGuard::from(&mut value);
    /// assert_eq!(*guard.expose(), 42);
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
    T: Zeroize + FastZeroizable + ZeroizationProbe,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'a, T> DerefMut for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + FastZeroizable + ZeroizationProbe,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
    }
}

impl<'a, T> FastZeroizable for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + FastZeroizable + ZeroizationProbe,
{
    fn fast_zeroize(&mut self) {
        let elements: [&mut dyn FastZeroizable; 1] = [to_fast_zeroizable_dyn_mut(&mut *self.inner)];
        zeroize_collection(&mut elements.into_iter());
    }
}

impl<'a, T> AssertZeroizeOnDrop for ZeroizingMutGuard<'a, T>
where
    T: Zeroize + FastZeroizable + ZeroizationProbe,
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
    T: Zeroize + FastZeroizable + ZeroizationProbe,
{
    fn is_zeroized(&self) -> bool {
        let elements: [&dyn ZeroizationProbe; 1] = [to_zeroization_probe_dyn_ref(&*self.inner)];
        collection_zeroed(&mut elements.into_iter())
    }
}
