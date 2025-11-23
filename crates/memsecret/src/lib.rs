// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Wrapper type that prevents accidental exposure of sensitive data.

#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
mod tests;

mod collections;
mod traits;

pub use traits::MemMove;

use core::fmt;

use memcode::{MemBytesRequired, MemDecodable, MemEncodable};
use memzer::{DropSentinel, Zeroizable, ZeroizationProbe};
use zeroize::Zeroize;

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
/// - **Automatic zeroization**: Inner value zeroized on drop via `#[zeroize(drop)]`
/// - **Drop verification**: Contains [`DropSentinel`] to verify zeroization happened
///
/// # Usage
///
/// ```rust
/// use memsecret::Secret;
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
///
/// // Auto-zeroizes on drop
/// ```
///
/// # Encoding with memcode
///
/// `Secret<T>` can be encoded and decoded via memcode:
///
/// ```rust
/// use memsecret::Secret;
/// use memcode::{MemBytesRequired, MemEncode, MemEncodeBuf};
///
/// let mut sensitive_data = vec![1u8, 2, 3];
/// let mut secret = Secret::from(&mut sensitive_data);
///
/// // sensitive_data is guaranteed to be zeroized
/// assert!(sensitive_data.iter().all(|&b| b == 0));
///
/// // Access the secret value
/// assert_eq!(secret.expose(), &vec![1u8, 2, 3]);
///
/// // Modify the secret value
/// secret.expose_mut().push(4);
/// assert_eq!(secret.expose(), &vec![1u8, 2, 3, 4]);
///
/// // Encode via memcode
/// let required_capacity = secret.mem_bytes_required().unwrap();
/// let mut buf = MemEncodeBuf::new(required_capacity);
///
/// secret.drain_into(&mut buf).unwrap();
///
/// // `secret` is now zeroized
/// assert!(secret.expose().iter().all(|&b| b == 0));
/// ```
#[derive(Zeroize, Default, PartialEq, Eq, memzer::MemZer, memcode::MemCodec)]
#[zeroize(drop)]
pub struct Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemEncodable + MemDecodable + MemBytesRequired,
{
    inner: T,
    #[memcode(default)]
    __drop_sentinel: DropSentinel,
}

impl<T> fmt::Debug for Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemEncodable + MemDecodable + MemBytesRequired,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED Secret]")
    }
}

impl<T> Secret<T>
where
    T: Zeroize + Zeroizable + ZeroizationProbe + MemEncodable + MemDecodable + MemBytesRequired,
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
    /// use memsecret::Secret;
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
            __drop_sentinel: DropSentinel::default(),
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
    /// use memsecret::Secret;
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
    /// use memsecret::Secret;
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
