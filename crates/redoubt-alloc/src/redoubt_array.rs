// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

use redoubt_zero::{
    FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeMetadata, ZeroizeOnDropSentinel,
};

/// A fixed-size array wrapper with automatic zeroization.
///
/// Unlike `RedoubtVec`, this type has a fixed size known at compile time.
/// It provides safe replacement of the entire array with zeroization of the source.
///
/// # Example
///
/// ```rust
/// use redoubt_alloc::RedoubtArray;
/// use redoubt_zero::ZeroizationProbe;
///
/// let mut arr = RedoubtArray::<u8, 32>::new();
/// let mut data = [42u8; 32];
/// arr.replace_from_mut_array(&mut data);
///
/// // Source is guaranteed to be zeroized
/// assert!(data.is_zeroized());
/// ```
#[derive(RedoubtZero)]
pub struct RedoubtArray<T, const N: usize>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    inner: Box<[T; N]>,
    __sentinel: ZeroizeOnDropSentinel,
}

#[cfg(any(test, feature = "test_utils"))]
impl<T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe + PartialEq, const N: usize> PartialEq
    for RedoubtArray<T, N>
{
    fn eq(&self, other: &Self) -> bool {
        // Skip __sentinel (metadata that changes during zeroization)
        self.inner == other.inner
    }
}

#[cfg(any(test, feature = "test_utils"))]
impl<T: FastZeroizable + ZeroizeMetadata + Eq + ZeroizationProbe, const N: usize> Eq
    for RedoubtArray<T, N>
{
}

impl<T, const N: usize> core::fmt::Debug for RedoubtArray<T, N>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RedoubtArray")
            .field("data", &"REDACTED")
            .field("len", &N)
            .finish()
    }
}

impl<T, const N: usize> RedoubtArray<T, N>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    /// Creates a new `RedoubtArray` with default-initialized elements.
    pub fn new() -> Self
    where
        T: Default,
    {
        Self {
            inner: Box::new(core::array::from_fn(|_| T::default())),
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Returns the number of elements in the array (always N).
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns `true` if the array contains no elements (always false unless N=0).
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Replaces the entire array from a mutable source, zeroizing the source.
    ///
    /// # Performance Note
    ///
    /// Uses `ptr::swap_nonoverlapping` to exchange contents with the source
    /// without creating intermediate copies that could spill to stack.
    pub fn replace_from_mut_array(&mut self, src: &mut [T; N]) {
        self.fast_zeroize();

        unsafe {
            // SAFETY: Both arrays have exactly N elements and are properly aligned
            // Swap exchanges contents without intermediate copies
            core::ptr::swap_nonoverlapping(src.as_mut_ptr(), self.inner.as_mut_ptr(), N);
        }

        // Zeroize source (which now contains the old self.inner values, all zeros)
        src.fast_zeroize();
    }

    /// Returns a slice containing the entire array.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.inner.as_ref()
    }

    /// Returns a mutable slice containing the entire array.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.inner.as_mut()
    }

    /// Returns a reference to the underlying array.
    #[inline]
    pub fn as_array(&self) -> &[T; N] {
        &*self.inner
    }

    /// Returns a mutable reference to the underlying array.
    #[inline]
    pub fn as_mut_array(&mut self) -> &mut [T; N] {
        &mut *self.inner
    }
}

impl<T, const N: usize> Default for RedoubtArray<T, N>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe + Default,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Deref for RedoubtArray<T, N>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &*self.inner
    }
}

impl<T, const N: usize> DerefMut for RedoubtArray<T, N>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.inner
    }
}
