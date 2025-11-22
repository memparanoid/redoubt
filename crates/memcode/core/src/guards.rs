// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! RAII guards for automatic zeroization on drop.

use zeroize::Zeroize;

/// Internal guard for zeroizing primitive types on drop.
///
/// Used internally by `MemEncode` implementations for scalars (`u8`, `u16`, `u32`, etc.)
/// to ensure values are zeroized after encoding.
///
/// **Note:** This is a `pub(crate)` internal type. For public API, use [`BytesGuard`].
pub(crate) struct PrimitiveGuard<'a, T: Zeroize> {
    inner: &'a mut T,
}

impl<'a, T: Zeroize> PrimitiveGuard<'a, T> {
    /// Creates a new guard wrapping a mutable reference to a primitive.
    ///
    /// The primitive will be zeroized when the guard is dropped.
    pub fn from(t: &'a mut T) -> Self {
        Self { inner: t }
    }
}

impl<'a, T: Zeroize> AsRef<T> for PrimitiveGuard<'a, T> {
    fn as_ref(&self) -> &T {
        self.inner
    }
}

impl<'a, T: Zeroize> Drop for PrimitiveGuard<'a, T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// RAII guard for byte slices that automatically zeroizes on drop.
///
/// `BytesGuard` wraps a mutable slice of bytes (`&mut [u8]`) and ensures that
/// the bytes are zeroized when the guard is dropped. This is useful for
/// protecting sensitive data during temporary operations.
///
/// # Design
///
/// - Wraps `&'a mut [u8]` (borrows the slice mutably)
/// - Implements `AsRef` and `AsMut` for convenient access
/// - Zeroizes the slice on drop via RAII
///
/// # Example
///
/// ```rust
/// use memcode_core::BytesGuard;
///
/// let mut sensitive = vec![1u8, 2, 3, 4, 5];
///
/// {
///     // Guard borrows `sensitive` and will zeroize it on drop
///     let guard = BytesGuard::from(sensitive.as_mut_slice());
///
///     // Access bytes via as_ref()/as_mut()
///     assert_eq!(guard.as_ref()[0], 1);
/// } // guard drops here → bytes are zeroized
///
/// assert!(sensitive.iter().all(|&b| b == 0));
/// ```
///
/// # Use Cases
///
/// - Temporary buffers for encoding/decoding
/// - Intermediate results during crypto operations
/// - Protecting slices during error handling
pub struct BytesGuard<'a> {
    bytes: &'a mut [u8],
}

impl<'a> BytesGuard<'a> {
    /// Creates a new guard wrapping a mutable byte slice.
    ///
    /// The slice will be zeroized when the guard is dropped.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memcode_core::BytesGuard;
    ///
    /// let mut data = vec![1u8, 2, 3];
    /// let guard = BytesGuard::from(data.as_mut_slice());
    ///
    /// assert_eq!(guard.as_ref().len(), 3);
    /// ```
    pub fn from(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> AsRef<[u8]> for BytesGuard<'a> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

impl<'a> AsMut<[u8]> for BytesGuard<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.bytes
    }
}

impl<'a> Drop for BytesGuard<'a> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
