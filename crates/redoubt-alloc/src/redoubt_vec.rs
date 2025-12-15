// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use redoubt_zero::{
    FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeMetadata, ZeroizeOnDropSentinel,
};

/// A Vec wrapper with automatic zeroization and safe reallocation.
///
/// When capacity is exceeded, `RedoubtVec` performs a safe reallocation:
/// 1. Allocates temporary storage with current data
/// 2. Zeroizes old allocation
/// 3. Re-allocates with 2x capacity
/// 4. Drains from temp (zeroizing temp)
///
/// This ensures no sensitive data is left in old allocations, at the cost
/// of performance (double allocation during growth).
///
/// # Example
///
/// ```rust
/// use redoubt_alloc::RedoubtVec;
///
/// let mut vec = RedoubtVec::new();
/// vec.push(42u8);
/// vec.push(43u8);
/// // Automatic safe reallocation when capacity is exceeded
/// ```
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub struct RedoubtVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    inner: Vec<T>,
    __sentinel: ZeroizeOnDropSentinel,
}

impl<T> RedoubtVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    /// Creates a new empty `RedoubtVec`.
    pub fn new() -> Self {
        Self {
            inner: Vec::new(),
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Creates a new `RedoubtVec` with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Returns the number of elements in the vector.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the vector contains no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the capacity of the vector.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Grows to at least `min_capacity` if needed.
    ///
    /// Rounds up to the next power of 2 to maintain efficient growth pattern
    /// (1 → 2 → 4 → 8 → 16...). Does nothing if current capacity is sufficient.
    ///
    /// # Safety Strategy
    ///
    /// 1. Allocate temp Vec with current data (memcpy for performance)
    /// 2. Zeroize old allocation
    /// 3. Re-allocate with new capacity (next power of 2)
    /// 4. Move data from temp back (memcpy + zeroize temp)
    ///
    /// # Performance Note
    ///
    /// Uses `ptr::copy_nonoverlapping` instead of `iter_mut() + mem::take()`
    /// because every nanosecond counts when handling sensitive data. The
    /// unsafe memcpy is significantly faster and avoids requiring `T: Clone`
    /// or `T: Default` bounds.
    ///
    /// By accepting `min_capacity` and doing a single grow, this is O(n) instead
    /// of O(n log n) when growing by large amounts.
    fn maybe_grow_to(&mut self, min_capacity: usize) {
        if self.capacity() >= min_capacity {
            return;
        }

        let current_len = self.len();
        let new_capacity = min_capacity.next_power_of_two();

        // 1. Allocate temp and copy current data
        let mut tmp = Vec::with_capacity(current_len);
        unsafe {
            // SAFETY: We're copying exactly len() elements from a valid Vec
            core::ptr::copy_nonoverlapping(self.inner.as_ptr(), tmp.as_mut_ptr(), current_len);
            tmp.set_len(current_len);
        }

        // 2. Zeroize old allocation
        self.inner.fast_zeroize();
        self.inner.clear();
        self.inner.shrink_to_fit();

        // 3. Re-allocate with new capacity
        self.inner.reserve_exact(new_capacity);

        // 4. Copy data back from tmp
        unsafe {
            // SAFETY: tmp has exactly current_len elements, self has sufficient capacity
            core::ptr::copy_nonoverlapping(tmp.as_ptr(), self.inner.as_mut_ptr(), current_len);
            self.inner.set_len(current_len);
        }

        // 5. Zeroize and drop tmp
        tmp.fast_zeroize();
    }

    /// Appends an element to the back of the vector.
    ///
    /// If capacity is exceeded, performs safe reallocation to next power of 2.
    pub fn push(&mut self, value: T) {
        self.maybe_grow_to(self.len() + 1);
        self.inner.push(value);
    }

    /// Drains from slice, zeroizing source.
    ///
    /// Grows the vector if necessary to accommodate the slice.
    pub fn drain_from_slice(&mut self, src: &mut [T])
    where
        T: Default,
    {
        self.maybe_grow_to(self.len() + src.len());

        // Drain elements using mem::take (moves ownership)
        for i in 0..src.len() {
            let item = core::mem::take(&mut src[i]);
            self.inner.push(item);
        }

        // Zeroize source (now contains Default values)
        src.fast_zeroize();
    }

    /// Drains from single value, zeroizing source.
    pub fn drain_from_value(&mut self, src: &mut T)
    where
        T: Default,
    {
        self.maybe_grow_to(self.len() + 1);

        let item = core::mem::take(src);
        self.inner.push(item);
        src.fast_zeroize();
    }

    /// Clears the vector, removing all values.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Returns a slice containing the entire vector.
    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    /// Returns a mutable slice containing the entire vector.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.inner
    }
}

impl<T> Default for RedoubtVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Deref for RedoubtVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for RedoubtVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
