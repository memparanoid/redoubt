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
/// use redoubt_zero::ZeroizationProbe;
///
/// let mut vec = RedoubtVec::new();
/// let mut data = [42u8, 43];
/// vec.extend_from_mut_slice(&mut data);
///
/// // Source is guaranteed to be zeroized
/// assert!(data.is_zeroized());
/// ```
#[derive(RedoubtZero)]
pub struct RedoubtVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    inner: Vec<T>,
    __sentinel: ZeroizeOnDropSentinel,
}

#[cfg(any(test, feature = "test_utils"))]
impl<T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe + PartialEq> PartialEq
    for RedoubtVec<T>
{
    fn eq(&self, other: &Self) -> bool {
        // Skip __sentinel (metadata that changes during zeroization)
        self.inner == other.inner
    }
}

#[cfg(any(test, feature = "test_utils"))]
impl<T: FastZeroizable + ZeroizeMetadata + Eq + ZeroizationProbe> Eq for RedoubtVec<T> {}

impl<T> core::fmt::Debug for RedoubtVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RedoubtVec")
            .field("data", &"REDACTED")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .finish()
    }
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
    #[cold]
    #[inline(never)]
    fn grow_to(&mut self, min_capacity: usize) {
        let current_len = self.len();
        let new_capacity = min_capacity.next_power_of_two();

        // 1. Allocate temp and copy current data
        let mut tmp = Vec::with_capacity(current_len);
        unsafe {
            // SAFETY (PRECONDITIONS ARE MET): copying exactly len() elements from valid Vec
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
            // SAFETY (PRECONDITIONS ARE MET): tmp has exactly current_len elements, self has sufficient capacity from reserve_exact
            core::ptr::copy_nonoverlapping(tmp.as_ptr(), self.inner.as_mut_ptr(), current_len);
            self.inner.set_len(current_len);
        }

        // 5. Zeroize and drop tmp
        tmp.fast_zeroize();
    }

    #[inline(always)]
    fn maybe_grow_to(&mut self, min_capacity: usize) {
        if self.capacity() >= min_capacity {
            return;
        }

        self.grow_to(min_capacity);
    }

    /// Extends from a mutable slice, zeroizing the source.
    ///
    /// Grows the vector if necessary to accommodate the slice.
    ///
    /// # Performance Note
    ///
    /// Uses `ptr::copy_nonoverlapping` for bulk copy instead of individual
    /// operations. This is significantly faster for large slices.
    pub fn extend_from_mut_slice(&mut self, src: &mut [T])
    where
        T: Default,
    {
        self.maybe_grow_to(self.len() + src.len());

        unsafe {
            // SAFETY (PRECONDITIONS ARE MET): src has exactly src.len() elements, self has sufficient capacity from maybe_grow_to
            let src_ptr = src.as_ptr();
            let dst_ptr = self.inner.as_mut_ptr().add(self.len());
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, src.len());
            self.inner.set_len(self.len() + src.len());
        }

        // Zeroize source
        src.fast_zeroize();
    }

    /// Drains a single value into the vector, zeroizing the source.
    pub fn drain_value(&mut self, src: &mut T)
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
        self.inner.fast_zeroize();
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

    /// Returns a reference to the inner Vec.
    ///
    /// This allows direct access to the underlying Vec for operations
    /// that require Vec-specific APIs, such as codec implementations.
    pub fn as_vec(&self) -> &Vec<T> {
        &self.inner
    }

    /// Returns a mutable reference to the inner Vec.
    ///
    /// This allows direct manipulation of the underlying Vec for operations
    /// that require Vec-specific APIs, such as codec implementations.
    pub fn as_mut_vec(&mut self) -> &mut Vec<T> {
        &mut self.inner
    }

    /// Initializes the vector to the specified size using the most efficient method.
    ///
    /// For types that can be bulk zeroized (primitives), this uses zero initialization
    /// which is extremely fast. For complex types, it uses `T::default()`.
    ///
    /// # Performance
    ///
    /// - If `T::CAN_BE_BULK_ZEROIZED == true`: O(1) memset operation
    /// - Otherwise: O(n) pushing defaults
    ///
    /// # Safety
    ///
    /// After calling this method, the vector will have exactly `size` elements,
    /// all properly initialized either to zero (if bulk zeroizable) or to their
    /// default value.
    #[cfg(feature = "default_init")]
    pub fn default_init_to_size(&mut self, size: usize)
    where
        T: Default,
    {
        self.clear();
        self.maybe_grow_to(size);

        if T::CAN_BE_BULK_ZEROIZED {
            // Zero init path (SUPER FAST for primitives like u8, u32, etc.)
            self.inner.fast_zeroize();
            // SAFETY: T can be bulk zeroized, so all-zeros is a valid state.
            // The inner vec has sufficient capacity from maybe_grow_to.
            unsafe {
                self.inner.set_len(size);
            }
        } else {
            // Default path for complex types
            for _ in 0..size {
                self.inner.push(T::default());
            }
            self.inner.fast_zeroize();
        }

        debug_assert_eq!(self.len(), size);
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
