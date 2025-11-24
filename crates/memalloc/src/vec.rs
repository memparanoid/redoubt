// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::{DropSentinel, MemZer, ZeroizationProbe};
use zeroize::Zeroize;

/// Error type for `AllockedVec` operations.
#[derive(Debug, thiserror::Error)]
pub enum AllockedVecError {
    /// Attempted to reserve capacity on an already-sealed vector.
    #[error("Vector is already sealed and cannot be resized")]
    AlreadySealed,

    /// Integer overflow when computing new length.
    ///
    /// This error is practically impossible to encounter in normal usage,
    /// as it would require a vector with length approaching `isize::MAX`.
    /// It exists as a defensive check for integer overflow safety.
    #[error("Integer overflow: total length would exceed usize::MAX")]
    Overflow,

    /// Attempted to push beyond the vector's capacity.
    #[error("Capacity exceeded: cannot push beyond sealed capacity")]
    CapacityExceeded,
}

/// Allocation-locked Vec that prevents reallocation after sealing.
///
/// Once `reserve_exact()` is called, the vector is sealed and cannot grow beyond
/// that capacity. All operations that would cause reallocation fail and zeroize data.
///
/// # Type Parameters
///
/// - `T`: The element type. Must implement `Zeroize` for automatic cleanup.
///
/// # Example
///
/// ```rust
/// use memalloc::AllockedVec;
///
/// let mut vec = AllockedVec::new();
/// vec.reserve_exact(5).unwrap();
///
/// vec.push(1u8).unwrap();
/// vec.push(2u8).unwrap();
///
/// assert_eq!(vec.len(), 2);
/// assert_eq!(vec.capacity(), 5);
/// ```
#[derive(Debug, Zeroize, MemZer)]
#[zeroize(drop)]
pub struct AllockedVec<T>
where
    T: Zeroize + ZeroizationProbe,
{
    inner: Vec<T>,
    has_been_sealed: bool,
    __drop_sentinel: DropSentinel,
}

impl<T> AllockedVec<T>
where
    T: Zeroize + ZeroizationProbe,
{
    fn try_drain_from(&mut self, slice: &mut [T]) -> Result<(), AllockedVecError>
    where
        T: Default + Zeroize,
    {
        // Note: checked_add overflow is practically impossible (requires len > isize::MAX),
        // but we keep this defensive check for integer overflow safety.
        let new_len = self
            .inner
            .len()
            .checked_add(slice.len())
            .ok_or(AllockedVecError::Overflow)?;

        if new_len > self.inner.capacity() {
            return Err(AllockedVecError::CapacityExceeded);
        }

        for item in slice.iter_mut() {
            let value = core::mem::take(item);
            self.inner.push(value);
        }

        Ok(())
    }

    /// Creates a new empty `AllockedVec` with zero capacity.
    ///
    /// The vector is not sealed until `reserve_exact()` is called.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let vec: AllockedVec<u8> = AllockedVec::new();
    /// assert_eq!(vec.len(), 0);
    /// assert_eq!(vec.capacity(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            inner: Vec::new(),
            has_been_sealed: false,
            __drop_sentinel: DropSentinel::default(),
        }
    }

    /// Creates a new `AllockedVec` with the specified capacity and seals it immediately.
    ///
    /// This is equivalent to calling `new()` followed by `reserve_exact(capacity)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let mut vec = AllockedVec::<u8>::with_capacity(10);
    /// assert_eq!(vec.len(), 0);
    /// assert_eq!(vec.capacity(), 10);
    /// // Already sealed - cannot reserve again
    /// assert!(vec.reserve_exact(20).is_err());
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        let mut vec = Self::new();
        vec.inner.reserve_exact(capacity);
        vec.has_been_sealed = true;
        vec
    }

    /// Reserves exact capacity and seals the vector.
    ///
    /// After calling this method, the vector is sealed and cannot be resized.
    /// Subsequent calls to `reserve_exact()` will fail.
    ///
    /// # Errors
    ///
    /// Returns [`AllockedVecError::AlreadySealed`] if the vector is already sealed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let mut vec: AllockedVec<u8> = AllockedVec::new();
    /// vec.reserve_exact(10).unwrap();
    ///
    /// // Second reserve fails
    /// assert!(vec.reserve_exact(20).is_err());
    /// ```
    pub fn reserve_exact(&mut self, capacity: usize) -> Result<(), AllockedVecError> {
        if self.has_been_sealed {
            return Err(AllockedVecError::AlreadySealed);
        }

        self.inner.reserve_exact(capacity);
        self.has_been_sealed = true;
        Ok(())
    }

    /// Pushes a value onto the end of the vector.
    ///
    /// # Errors
    ///
    /// Returns [`AllockedVecError::CapacityExceeded`] if the vector is at capacity.
    /// On error, the vector is zeroized.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let mut vec = AllockedVec::with_capacity(2);
    /// vec.push(1u8).unwrap();
    /// vec.push(2u8).unwrap();
    ///
    /// // Exceeds capacity
    /// assert!(vec.push(3u8).is_err());
    /// ```
    pub fn push(&mut self, value: T) -> Result<(), AllockedVecError> {
        if self.inner.len() >= self.inner.capacity() {
            self.zeroize();
            return Err(AllockedVecError::CapacityExceeded);
        }

        self.inner.push(value);
        Ok(())
    }

    /// Drains values from a mutable slice into the vector.
    ///
    /// The source slice is zeroized after draining (each element replaced with `T::default()`).
    ///
    /// # Errors
    ///
    /// Returns [`AllockedVecError::CapacityExceeded`] if adding all elements would exceed capacity.
    /// On error, both the source slice and vector are zeroized.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let mut vec = AllockedVec::with_capacity(5);
    /// let mut data = vec![1u8, 2, 3, 4, 5];
    ///
    /// vec.drain_from(&mut data).unwrap();
    ///
    /// assert_eq!(vec.len(), 5);
    /// assert!(data.iter().all(|&x| x == 0)); // Source zeroized
    /// ```
    pub fn drain_from(&mut self, slice: &mut [T]) -> Result<(), AllockedVecError>
    where
        T: Default + Zeroize,
    {
        let result = self.try_drain_from(slice);

        if result.is_err() {
            self.zeroize();
            // Zeroize each element in slice manually
            for item in slice.iter_mut() {
                item.zeroize();
            }
        }

        result
    }

    /// Returns the number of elements in the vector.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let mut vec = AllockedVec::with_capacity(10);
    /// vec.push(1u8).unwrap();
    /// assert_eq!(vec.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns the total capacity of the vector.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let vec: AllockedVec<u8> = AllockedVec::with_capacity(10);
    /// assert_eq!(vec.capacity(), 10);
    /// ```
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns `true` if the vector contains no elements.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let vec: AllockedVec<u8> = AllockedVec::new();
    /// assert!(vec.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns an immutable slice view of the vector.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let mut vec = AllockedVec::with_capacity(3);
    /// vec.push(1u8).unwrap();
    /// vec.push(2u8).unwrap();
    ///
    /// assert_eq!(vec.as_slice(), &[1, 2]);
    /// ```
    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    /// Returns a mutable slice view of the vector.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::AllockedVec;
    ///
    /// let mut vec = AllockedVec::with_capacity(3);
    /// vec.push(1u8).unwrap();
    /// vec.push(2u8).unwrap();
    ///
    /// vec.as_mut_slice()[0] = 42;
    /// assert_eq!(vec.as_slice(), &[42, 2]);
    /// ```
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.inner
    }
}

impl<T> Default for AllockedVec<T>
where
    T: Zeroize + ZeroizationProbe,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> core::ops::Deref for AllockedVec<T>
where
    T: Zeroize + ZeroizationProbe,
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
