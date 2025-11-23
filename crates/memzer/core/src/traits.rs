// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
//! Core traits for systematic zeroization.

use zeroize::Zeroize;

use super::drop_sentinel::DropSentinel;

/// Trait for types that can be systematically zeroized.
///
/// This trait provides a unified interface for zeroizing types, complementing
/// the [`zeroize::Zeroize`] trait. `Zeroizable` is used internally by guards
/// and collections to ensure all fields are zeroized.
///
/// # Difference from `Zeroize`
///
/// - `Zeroize`: External trait from the `zeroize` crate (standard interface)
/// - `Zeroizable`: Internal trait for `memzer` (allows custom behavior like [`DropSentinel::zeroize`])
///
/// Most types implement `Zeroizable` by delegating to `Zeroize::zeroize()`.
///
/// # Example
///
/// ```rust
/// use memzer_core::Zeroizable;
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize)]
/// struct MyType {
///     data: Vec<u8>,
/// }
///
/// impl Zeroizable for MyType {
///     fn self_zeroize(&mut self) {
///         self.zeroize(); // Delegate to Zeroize
///     }
/// }
/// ```
pub trait Zeroizable {
    /// Zeroizes the value in place.
    ///
    /// After calling this method, the value should be in a "zeroed" state
    /// (all bytes set to 0).
    fn self_zeroize(&mut self);
}

/// Trait for verifying that a value has been zeroized.
///
/// This trait allows runtime checks to verify that zeroization actually happened.
/// Used in tests and assertions to ensure no sensitive data remains in memory.
///
/// # Example
///
/// ```rust
/// use memzer_core::{ZeroizationProbe, Zeroizable, primitives::U32};
///
/// let mut value = U32::default();
/// *value.expose_mut() = 42;
///
/// assert!(!value.is_zeroized());
///
/// value.self_zeroize();
/// assert!(value.is_zeroized());
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
/// Types implementing this trait contain a [`DropSentinel`] and provide
/// methods to verify that `.zeroize()` was called before the value is dropped.
///
/// This trait is typically derived using `#[derive(MemZer)]` from the `memzer` crate.
pub trait AssertZeroizeOnDrop {
    /// Clones the internal [`DropSentinel`] for verification.
    ///
    /// This is used by [`assert_zeroize_on_drop`](AssertZeroizeOnDrop::assert_zeroize_on_drop)
    /// to verify zeroization after the value is dropped.
    fn clone_drop_sentinel(&self) -> DropSentinel;

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
/// use memzer_core::{MutGuarded, ZeroizingMutGuard};
///
/// fn process_guarded<'a, T: MutGuarded<'a, SomeType>>(guard: &mut T) {
///     let value = guard.expose_mut();
///     // ... use value
/// } // guard zeroizes on drop
/// ```
pub trait MutGuarded<'a, T>: Zeroizable + ZeroizationProbe + AssertZeroizeOnDrop
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    /// Exposes an immutable reference to the guarded value.
    fn expose(&self) -> &T;

    /// Exposes a mutable reference to the guarded value.
    fn expose_mut(&mut self) -> &mut T;
}
