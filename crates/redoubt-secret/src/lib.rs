// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Wrapper type that prevents accidental exposure of sensitive data.
#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(test)]
mod tests;

mod collections;
mod traits;

pub use traits::MemMove;

use core::fmt;

use redoubt_codec::{BytesRequired, Decode, Encode, RedoubtCodec};
use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeOnDropSentinel};

/// Wrapper that prevents accidental exposure of sensitive data.
///
/// `Secret<T>` wraps a value `T` and prevents direct access to it, forcing
/// controlled access via [`expose()`](Secret::expose) and [`expose_mut()`](Secret::expose_mut).
/// This prevents accidental copies, leaks via `Debug`, and other unintended exposures.
///
/// # Design Principles
///
/// - **No `Deref`/`DerefMut`**: Cannot accidentally access inner value via `*secret`
/// - **No `Clone`**: Prevents unintended copies of sensitive data
/// - **Redacted `Debug`**: Prints `[REDACTED Secret]` instead of inner value
/// - **Caller must zeroize**: Caller is responsible for zeroizing the exposed value when done
/// - **Drop verification**: Contains [`ZeroizeOnDropSentinel`] to verify zeroization happened
///
/// # Usage
///
/// ```rust
/// use redoubt_secret::Secret;
///
/// let mut sensitive_data = [197u8; 32];
/// let mut secret = Secret::from(&mut sensitive_data);
///
/// // sensitive_data is guaranteed to be zeroized
/// assert!(sensitive_data.iter().all(|&b| b == 0));
///
/// // Access immutably
/// assert!(secret.expose().iter().all(|&b| b == 197));
///
/// // Access mutably
/// secret.expose_mut().iter_mut().for_each(|b| *b = 0xFF);
/// assert!(secret.expose().iter().all(|&b| b == 0xFF));
/// ```
#[derive(Default, PartialEq, Eq, RedoubtZero, RedoubtCodec)]
pub struct Secret<T>
where
    T: FastZeroizable + ZeroizationProbe + Encode + Decode + BytesRequired,
{
    inner: T,
    #[codec(default)]
    __sentinel: ZeroizeOnDropSentinel,
}

impl<T> fmt::Debug for Secret<T>
where
    T: FastZeroizable + ZeroizationProbe + Encode + Decode + BytesRequired,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED Secret]")
    }
}

impl<T> Secret<T>
where
    T: FastZeroizable + ZeroizationProbe + Encode + Decode + BytesRequired,
{
    /// Creates a new `Secret` by moving data from `sensitive_data`, zeroizing the source.
    ///
    /// This method uses [`MemMove`](crate::MemMove) to transfer data without creating
    /// unzeroized copies. The source `sensitive_data` is guaranteed to be zeroized after this call.
    ///
    /// The value is stored securely and can only be accessed via
    /// [`expose()`](Secret::expose) and [`expose_mut()`](Secret::expose_mut).
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_secret::Secret;
    ///
    /// let mut sensitive_data = [197u8; 32];
    /// let secret = Secret::from(&mut sensitive_data);
    ///
    /// // sensitive_data is guaranteed to be zeroized
    /// assert!(sensitive_data.iter().all(|&b| b == 0));
    ///
    /// assert!(secret.expose().iter().all(|&b| b == 197));
    /// ```
    pub fn from(sensitive_data: &mut T) -> Self
    where
        T: MemMove + Default,
    {
        let mut inner = T::default();
        T::mem_move(sensitive_data, &mut inner);

        Self {
            inner,
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Exposes an immutable reference to the inner value.
    ///
    /// This is the **only** way to read the inner value. The reference
    /// cannot outlive the `Secret`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_secret::Secret;
    ///
    /// let mut sensitive_data = [197u8; 32];
    /// let secret = Secret::from(&mut sensitive_data);
    ///
    /// // sensitive_data is guaranteed to be zeroized
    /// assert!(sensitive_data.iter().all(|&b| b == 0));
    ///
    /// assert!(secret.expose().iter().all(|&b| b == 197));
    /// ```
    pub fn expose(&self) -> &T {
        &self.inner
    }

    /// Exposes a mutable reference to the inner value.
    ///
    /// This is the **only** way to modify the inner value. The reference
    /// cannot outlive the `Secret`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_secret::Secret;
    ///
    /// let mut sensitive_data = [197u8; 32];
    /// let mut secret = Secret::from(&mut sensitive_data);
    ///
    /// // sensitive_data is guaranteed to be zeroized
    /// assert!(sensitive_data.iter().all(|&b| b == 0));
    ///
    /// secret.expose_mut().iter_mut().for_each(|b| *b = 0xFF);
    /// assert!(secret.expose().iter().all(|&b| b == 0xFF));
    /// ```
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}
