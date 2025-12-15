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
///
/// let mut s = RedoubtString::new();
/// s.push_str("secret");
/// // Automatic safe reallocation when capacity is exceeded
/// ```
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub struct RedoubtString {
    inner: String,
    __sentinel: ZeroizeOnDropSentinel,
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
    fn maybe_grow_to(&mut self, min_capacity: usize) {
        if self.capacity() >= min_capacity {
            return;
        }

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
        self.drain_from_string(&mut tmp);
    }

    /// Appends a given string slice onto the end of this String.
    ///
    /// If capacity is exceeded, performs safe reallocation to next power of 2.
    pub fn push_str(&mut self, s: &str) {
        self.maybe_grow_to(self.len() + s.len());
        self.inner.push_str(s);
    }

    /// Appends a char to the end of this String.
    pub fn push(&mut self, ch: char) {
        self.maybe_grow_to(self.len() + ch.len_utf8());
        self.inner.push(ch);
    }

    /// Drains from String, zeroizing and clearing source.
    pub fn drain_from_string(&mut self, src: &mut String) {
        self.maybe_grow_to(self.len() + src.len());

        self.inner.push_str(src);

        // Zeroize and clear source
        src.fast_zeroize();
        src.clear();
    }

    /// Copies from str (no zeroization, src is immutable).
    pub fn copy_from_str(&mut self, src: &str) {
        self.maybe_grow_to(self.len() + src.len());
        self.inner.push_str(src);
    }

    /// Clears the string, removing all contents.
    pub fn clear(&mut self) {
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

impl From<String> for RedoubtString {
    fn from(mut s: String) -> Self {
        let mut redoubt = Self::with_capacity(s.len());
        redoubt.drain_from_string(&mut s);
        redoubt
    }
}

impl From<&str> for RedoubtString {
    fn from(s: &str) -> Self {
        let mut redoubt = Self::with_capacity(s.len());
        redoubt.copy_from_str(s);
        redoubt
    }
}
