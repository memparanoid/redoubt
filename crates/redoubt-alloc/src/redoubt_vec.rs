// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeMetadata};

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
#[fast_zeroize(drop)]
pub struct RedoubtVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    inner: Vec<T>,
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
impl<T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe + PartialEq> PartialEq
    for RedoubtVec<T>
{
    fn eq(&self, other: &Self) -> bool {
        // Skip __sentinel (metadata that changes during zeroization)
        self.inner == other.inner
    }
}

#[cfg(any(test, feature = "test-utils"))]
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
            #[cfg(test)]
            __sentinel: redoubt_zero::ZeroizeOnDropSentinel::default(),
        }
    }

    /// Creates a new `RedoubtVec` with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut vec = Self {
            inner: Vec::with_capacity(capacity),
            #[cfg(test)]
            __sentinel: redoubt_zero::ZeroizeOnDropSentinel::default(),
        };

        vec.inner.fast_zeroize();

        vec
    }

    /// Creates a new `RedoubtVec` from a mutable slice, zeroizing the source.
    pub fn from_mut_slice(src: &mut [T]) -> Self
    where
        T: Default,
    {
        let mut vec = Self::new();
        vec.extend_from_mut_slice(src);
        vec
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
    /// 3. Re-allocate with new capacity (next power of 2), and zeroize all of it
    /// 4. Move data from temp back (memcpy + zeroize temp)
    ///
    /// # Why a raw copy
    ///
    /// `iter_mut() + mem::take()` would need `T: Clone` or `T: Default` and
    /// is slower element by element. The copy is [`redoubt_mem`]'s and not
    /// `core::ptr`'s: a length the compiler cannot see is a call into the C
    /// library's `memcpy`, and glibc's leaves the bytes in vector registers
    /// nothing afterwards writes over. This one erases what it used.
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

        // SAFETY: the count is the source's own length, so it is inside both
        // that allocation and `tmp`, which was reserved for exactly it. `tmp`
        // is a local, so neither range reaches the other, and the copy is what
        // initializes the elements the length below declares.
        unsafe {
            redoubt_mem::copy_nonoverlapping(self.inner.as_ptr(), tmp.as_mut_ptr(), current_len);
            tmp.set_len(current_len);
        }

        // 2. Zeroize old allocation
        self.inner.fast_zeroize();
        self.inner.clear();
        self.inner.shrink_to_fit();

        // 3. Re-allocate with new capacity
        self.inner.reserve_exact(new_capacity);
        self.inner.fast_zeroize();

        // 4. Copy data back from tmp
        // SAFETY: `tmp` holds exactly `current_len`, and `reserve_exact` above
        // is what leaves room for at least that many — `new_capacity` is a
        // power of two at or past it. `tmp` is a local, so neither range
        // reaches the other, and the copy is what initializes the elements the
        // length below declares.
        unsafe {
            redoubt_mem::copy_nonoverlapping(tmp.as_ptr(), self.inner.as_mut_ptr(), current_len);
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
    /// # Why a raw copy
    ///
    /// One bulk move instead of an operation per element. [`redoubt_mem`]'s,
    /// for the reason [`Self::grow_to`] gives.
    pub fn extend_from_mut_slice(&mut self, src: &mut [T])
    where
        T: Default,
    {
        self.maybe_grow_to(self.len() + src.len());

        // SAFETY: `maybe_grow_to` above is what leaves room for `len` plus the
        // source, so the offset and the elements written from it are both in
        // the allocation. `src` is the caller's own slice, a different one,
        // and the copy is what initializes the elements the length below
        // declares.
        unsafe {
            let src_ptr = src.as_ptr();
            let dst_ptr = self.inner.as_mut_ptr().add(self.len());
            redoubt_mem::copy_nonoverlapping(src_ptr, dst_ptr, src.len());
            self.inner.set_len(self.len() + src.len());
        }

        // Zeroize source
        src.fast_zeroize();
    }

    /// Replaces the vector contents with data from a mutable slice, zeroizing both
    /// the old contents and the source.
    pub fn replace_from_mut_slice(&mut self, src: &mut [T])
    where
        T: Default,
    {
        self.clear();
        self.extend_from_mut_slice(src);
    }

    /// Drains a single value into the vector, zeroizing the source.
    pub fn drain_value(&mut self, src: &mut T)
    where
        T: Default,
    {
        self.maybe_grow_to(self.len() + 1);

        let at = self.inner.len();

        self.inner.push(T::default());

        redoubt_mem::swap(src, &mut self.inner[at]);

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
