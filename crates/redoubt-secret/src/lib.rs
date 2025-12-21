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

use core::fmt;

use redoubt_codec::{BytesRequired, Decode, Encode, RedoubtCodec};
use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeOnDropSentinel};

/// Wrapper that prevents accidental exposure of sensitive data.
///
/// `RedoubtSecret<T>` wraps a value `T` and provides controlled access via
/// [`as_ref()`](RedoubtSecret::as_ref) and [`as_mut()`](RedoubtSecret::as_mut).
/// This prevents accidental copies and leaks via `Debug`.
///
/// # Design Principles
///
/// - **No `Deref`/`DerefMut`**: Prevents accidental copies of `Copy` types via `*secret`
/// - **No `Clone`**: Prevents unintended copies of sensitive data
/// - **Redacted `Debug`**: Prints `[REDACTED RedoubtSecret]` instead of inner value
/// - **Drop verification**: Contains [`ZeroizeOnDropSentinel`] to verify zeroization happened
///
/// # Usage
///
/// ```rust
/// use redoubt_secret::RedoubtSecret;
///
/// // Create from sensitive data (when you don't have an instance yet)
/// let mut pin_code = 1234u64;
/// let secret = RedoubtSecret::from(&mut pin_code);
///
/// // pin_code is guaranteed to be zeroized
/// assert_eq!(pin_code, 0);
/// assert_eq!(secret.as_ref(), &1234);
///
/// // Replace when you already have an instance
/// let mut secret2 = RedoubtSecret::<u32>::default();
/// let mut session_id = 0xDEADBEEF;
/// secret2.replace(&mut session_id);
///
/// // session_id is guaranteed to be zeroized
/// assert_eq!(session_id, 0);
/// assert_eq!(secret2.as_ref(), &0xDEADBEEF);
/// ```
///
/// # ⚠️ Warning: Dereferencing with Copy types
///
/// **NEVER** dereference `as_ref()` or `as_mut()` when `T` implements `Copy`.
/// This will create a copy of the sensitive data, defeating the purpose of `RedoubtSecret`:
///
/// ```rust,no_run
/// use redoubt_secret::RedoubtSecret;
///
/// let mut secret = RedoubtSecret::<u64>::default();
/// let mut token = 0xDEADBEEF;
/// secret.replace(&mut token);
///
/// // ❌ DANGEROUS: Creates a copy of the secret value!
/// let leaked_copy = *secret.as_ref();  // This leaks sensitive data!
///
/// // ✅ SAFE: Only uses a reference
/// assert_eq!(secret.as_ref(), &0xDEADBEEF);
/// ```
#[derive(Default, PartialEq, Eq, RedoubtZero, RedoubtCodec)]
pub struct RedoubtSecret<T>
where
    T: FastZeroizable + ZeroizationProbe + Encode + Decode + BytesRequired,
{
    inner: T,
    #[codec(default)]
    __sentinel: ZeroizeOnDropSentinel,
}

impl<T> fmt::Debug for RedoubtSecret<T>
where
    T: FastZeroizable + ZeroizationProbe + Encode + Decode + BytesRequired,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED RedoubtSecret]")
    }
}

impl<T> RedoubtSecret<T>
where
    T: FastZeroizable + ZeroizationProbe + Encode + Decode + BytesRequired,
{
    /// Creates a new `RedoubtSecret` by moving data from `sensitive_data`, zeroizing the source.
    ///
    /// This method uses [`core::mem::swap`] to transfer data without creating
    /// unzeroized copies. The source `sensitive_data` is guaranteed to be zeroized after this call.
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_secret::RedoubtSecret;
    ///
    /// let mut api_key = 0xDEADBEEFCAFEBABEu64;
    /// let secret = RedoubtSecret::from(&mut api_key);
    ///
    /// // api_key is guaranteed to be zeroized
    /// assert_eq!(api_key, 0);
    ///
    /// assert_eq!(secret.as_ref(), &0xDEADBEEFCAFEBABE);
    /// ```
    pub fn from(sensitive_data: &mut T) -> Self
    where
        T: Default,
    {
        let mut secret = Self::default();
        secret.replace(sensitive_data);
        secret
    }

    /// Replaces the inner value with a new one, zeroizing both the old value and the source.
    ///
    /// This method:
    /// 1. Zeroizes the current inner value
    /// 2. Swaps the new value from `value` into `self`
    /// 3. Zeroizes the source (which now contains the old value)
    ///
    /// # Example
    ///
    /// ```rust
    /// use redoubt_secret::RedoubtSecret;
    ///
    /// let mut secret = RedoubtSecret::<u64>::default();
    /// let mut token = 0xCAFEBABE;
    /// secret.replace(&mut token);
    ///
    /// // token is guaranteed to be zeroized
    /// assert_eq!(token, 0);
    ///
    /// // secret now contains the value
    /// assert_eq!(*secret.as_ref(), 0xCAFEBABE);
    /// ```
    pub fn replace(&mut self, value: &mut T) {
        // Zeroize old value
        self.inner.fast_zeroize();

        // Swap values (moves value into self, moves old self into value)
        core::mem::swap(&mut self.inner, value);

        // Zeroize source (which now contains the old zeroized value)
        value.fast_zeroize();
    }

    /// Returns an immutable reference to the inner value.
    #[inline]
    pub fn as_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the inner value.
    #[inline]
    pub fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}
