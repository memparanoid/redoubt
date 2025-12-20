// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::string::String;
use core::ops::{Deref, DerefMut};

use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizeOnDropSentinel};

/// A String wrapper with automatic zeroization and safe reallocation.
///
/// When capacity is exceeded, `RedoubtString` performs a safe reallocation:
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
/// use redoubt_alloc::RedoubtString;
/// use redoubt_zero::ZeroizationProbe;
///
/// let mut s = RedoubtString::new();
/// let mut secret = String::from("password123");
/// s.extend_from_mut_string(&mut secret);
///
/// // Source is guaranteed to be zeroized
/// assert!(secret.is_zeroized());
/// ```
#[derive(RedoubtZero)]
pub struct RedoubtString {
    inner: String,
    __sentinel: ZeroizeOnDropSentinel,
}

#[cfg(any(test, feature = "test_utils"))]
impl PartialEq for RedoubtString {
    fn eq(&self, other: &Self) -> bool {
        // Skip __sentinel (metadata that changes during zeroization)
        self.inner == other.inner
    }
}

#[cfg(any(test, feature = "test_utils"))]
impl Eq for RedoubtString {}

impl core::fmt::Debug for RedoubtString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RedoubtString")
            .field("data", &"REDACTED")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .finish()
    }
}

impl RedoubtString {
    /// Creates a new empty `RedoubtString`.
    pub fn new() -> Self {
        Self {
            inner: String::new(),
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Creates a new `RedoubtString` with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: String::with_capacity(capacity),
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// Creates a new `RedoubtString` from a mutable String, zeroizing the source.
    pub fn from_mut_string(src: &mut String) -> Self {
        let mut s = Self::new();
        s.extend_from_mut_string(src);
        s
    }

    /// Creates a new `RedoubtString` from a string slice.
    pub fn from_str(src: &str) -> Self {
        let mut s = Self::new();
        s.extend_from_str(src);
        s
    }

    /// Returns the length of the string in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the string has a length of zero.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the capacity of the string in bytes.
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
    /// 1. Allocate temp String with current data
    /// 2. Zeroize old allocation
    /// 3. Re-allocate with new capacity (next power of 2)
    /// 4. Drain from temp (zeroizes temp)
    ///
    /// By accepting `min_capacity` and doing a single grow, this is O(n) instead
    /// of O(n log n) when growing by large amounts.
    #[cold]
    #[inline(never)]
    fn grow_to(&mut self, min_capacity: usize) {
        let new_capacity = min_capacity.next_power_of_two();

        // 1. Create temp with current data
        let mut tmp = self.inner.clone();

        // 2. Zeroize old allocation
        self.inner.fast_zeroize();
        self.inner.clear();
        self.inner.shrink_to_fit();

        // 3. Re-allocate with new capacity
        self.inner.reserve_exact(new_capacity);

        // 4. Drain from tmp
        self.extend_from_mut_string(&mut tmp);
    }

    #[inline(always)]
    fn maybe_grow_to(&mut self, min_capacity: usize) {
        if self.capacity() >= min_capacity {
            return;
        }

        self.grow_to(min_capacity);
    }

    /// Extends from a mutable String, zeroizing the source.
    pub fn extend_from_mut_string(&mut self, src: &mut String) {
        self.maybe_grow_to(self.len() + src.len());

        self.inner.push_str(src);

        // Zeroize and clear source
        src.fast_zeroize();
        src.clear();
    }

    /// Extends from str (no zeroization, src is immutable).
    pub fn extend_from_str(&mut self, src: &str) {
        self.maybe_grow_to(self.len() + src.len());
        self.inner.push_str(src);
    }

    /// Clears the string, removing all contents.
    pub fn clear(&mut self) {
        self.inner.fast_zeroize();
        self.inner.clear();
    }

    /// Returns a string slice containing the entire string.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Returns a mutable string slice.
    pub fn as_mut_str(&mut self) -> &mut str {
        &mut self.inner
    }

    /// Returns a reference to the inner String.
    ///
    /// This allows direct access to the underlying String for operations
    /// that require String-specific APIs, such as codec implementations.
    pub fn as_string(&self) -> &String {
        &self.inner
    }

    /// Returns a mutable reference to the inner String.
    ///
    /// This allows direct manipulation of the underlying String for operations
    /// that require String-specific APIs, such as codec implementations or `drain_string`.
    pub fn as_mut_string(&mut self) -> &mut String {
        &mut self.inner
    }
}

impl Default for RedoubtString {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for RedoubtString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for RedoubtString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
