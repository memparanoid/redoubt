// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::ops::{Deref, DerefMut};

use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeMetadata};

use alloc::boxed::Box;

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
#[fast_zeroize(drop)]
pub struct RedoubtArray<T, const N: usize>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    inner: Box<[T; N]>,
    /// Runtime verification that zeroization happened, for the tests that
    /// read it.
    ///
    /// Gated because it is an `Arc<AtomicBool>` — one heap allocation per
    /// value, in a type whose whole reason for existing is to leave nothing
    /// in memory. Nothing reads it outside this crate's own tests, and the
    /// `RedoubtZero` derive treats the field as optional.
    #[cfg(test)]
    __sentinel: redoubt_zero::ZeroizeOnDropSentinel,
}

#[cfg(any(test, feature = "test-utils"))]
impl<T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe + PartialEq, const N: usize> PartialEq
    for RedoubtArray<T, N>
{
    fn eq(&self, other: &Self) -> bool {
        // Skip __sentinel (metadata that changes during zeroization)
        self.inner == other.inner
    }
}

#[cfg(any(test, feature = "test-utils"))]
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
            #[cfg(test)]
            __sentinel: redoubt_zero::ZeroizeOnDropSentinel::default(),
        }
    }

    /// Creates a new `RedoubtArray` from a mutable array, zeroizing the source.
    pub fn from_mut_array(src: &mut [T; N]) -> Self
    where
        T: Default,
    {
        let mut arr = Self::new();
        arr.replace_from_mut_array(src);
        arr
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
    /// The copy is [`redoubt_mem`]'s and not `core`'s, which moves the bytes
    /// through registers it leaves as it found them.
    pub fn replace_from_mut_array(&mut self, src: &mut [T; N]) {
        // This wipe is an implementation detail (clearing the old contents
        // before the swap), not end-of-life zeroization — but fast_zeroize()
        // also marks the sentinel. Without the reset, the flag stays "already
        // zeroized" on a value that is about to hold live data, and
        // assert_zeroize_on_drop rejects it on arrival: the drop assertion
        // becomes impossible to state, since this is the constructor path the
        // test builds the value through. Other internal fast_zeroize() calls
        // in the workspace don't need the reset — they either wipe `inner`
        // only, or never sit on the construction path of a drop assertion.
        self.fast_zeroize();

        #[cfg(test)]
        self.__sentinel.reset();

        // SAFETY: both arrays are `[T; N]`, so each is N elements long and
        // aligned for one, and `src` is a separate value from `self`.
        unsafe {
            redoubt_mem::copy_nonoverlapping(src.as_ptr(), self.inner.as_mut_ptr(), N);
        }

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
        &self.inner
    }

    /// Returns a mutable reference to the underlying array.
    #[inline]
    pub fn as_mut_array(&mut self) -> &mut [T; N] {
        &mut self.inner
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
