// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Core traits for systematic zeroization.

use super::zeroize_on_drop_sentinel::ZeroizeOnDropSentinel;

/// Trait for verifying that a value has been zeroized.
///
/// This trait allows runtime checks to verify that zeroization actually happened.
/// Used in tests and assertions to ensure no sensitive data remains in memory.
///
/// # Example
///
/// ```rust
/// use redoubt_zero_core::{ZeroizationProbe, FastZeroizable};
///
/// let mut value: u32 = 42;
///
/// assert!(!value.is_zeroized());
///
/// value.fast_zeroize();
/// assert!(value.is_zeroized());
/// assert_eq!(value, 0);
/// ```
pub trait ZeroizationProbe {
    /// Returns `true` if the value is zeroized (all bytes are 0).
    ///
    /// This method should perform a runtime check to verify that the value
    /// has been properly zeroized.
    fn is_zeroized(&self) -> bool;
}

/// Trait for types that verify zeroization happened before drop.
///
/// Types implementing this trait contain a [`ZeroizeOnDropSentinel`] and provide
/// methods to verify that `.zeroize()` was called before the value is dropped.
///
/// This trait is typically derived using `#[derive(RedoubtZero)]` from the `RedoubtZero` crate.
pub trait AssertZeroizeOnDrop {
    /// Clones the internal [`ZeroizeOnDropSentinel`] for verification.
    ///
    /// This is used by [`assert_zeroize_on_drop`](AssertZeroizeOnDrop::assert_zeroize_on_drop)
    /// to verify zeroization after the value is dropped.
    fn clone_sentinel(&self) -> ZeroizeOnDropSentinel;

    /// Asserts that zeroization happens when this value is dropped.
    ///
    /// # Panics
    ///
    /// Panics if `.zeroize()` was not called before drop.
    ///
    /// This is typically used in tests to verify drop behavior for types
    /// that implement this trait.
    fn assert_zeroize_on_drop(self);
}

/// Trait for mutable guards that auto-zeroize on drop.
///
/// Types implementing this trait wrap a mutable reference `&mut T` and
/// provide controlled access while ensuring zeroization on drop.
///
/// # Example
///
/// ```rust,ignore
/// use redoubt_zero_core::{MutGuarded, ZeroizingMutGuard};
///
/// fn process_guarded<'a, T: MutGuarded<'a, SomeType>>(guard: &mut T) {
///     let value = guard.expose_mut();
///     // ... use value
/// } // guard zeroizes on drop
/// ```
pub trait MutGuarded<'a, T>: FastZeroize + ZeroizationProbe + AssertZeroizeOnDrop
where
    T: FastZeroize + ZeroizationProbe,
{
    /// Exposes an immutable reference to the guarded value.
    fn expose(&self) -> &T;

    /// Exposes a mutable reference to the guarded value.
    fn expose_mut(&mut self) -> &mut T;
}

/// Whether a type is emptied by writing zeros over its bytes, or field by field.
///
/// # Safety
///
/// `CAN_BE_BULK_ZEROIZED = true` promises that every byte zero is a value of
/// `Self`. Collections of `Self` then write zeros over their elements and keep
/// them, so a type holding a reference, a `Box`, a `NonZero` or an enum with no
/// variant at zero that says `true` leaves values it does not have.
pub unsafe trait ZeroizeMetadata {
    /// Whether every byte zero is a value of `Self`.
    const CAN_BE_BULK_ZEROIZED: bool;
}

/// Trait for types that can be zeroized at runtime.
///
/// This trait is dyn-compatible, allowing it to be used in trait objects
/// like `&mut dyn FastZeroizable`.
///
/// Use this trait when you need dynamic dispatch for zeroization operations.
pub trait FastZeroizable {
    /// Zeroizes the value in place.
    ///
    /// After calling this method, all sensitive data should be overwritten with zeros.
    fn fast_zeroize(&mut self);
}

/// [`ZeroizeMetadata`] and [`FastZeroizable`] together, which every type
/// implementing both has.
pub trait FastZeroize: ZeroizeMetadata + FastZeroizable {}

// Blanket impl: any type implementing both sub-traits automatically gets FastZeroize
impl<T: ZeroizeMetadata + FastZeroizable> FastZeroize for T {}
