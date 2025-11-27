// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use thiserror::Error;

use memzer::{DropSentinel, MemZer, ZeroizationProbe};
use zeroize::Zeroize;

/// Error type for `AllockedVec` operations.
#[derive(Debug, Error, Eq, PartialEq)]
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

/// Test behaviour for injecting failures in `AllockedVec` operations.
///
/// This is only available with the `test_utils` feature and allows users
/// to test error handling paths in their code by injecting failures.
///
/// The behaviour is sticky - once set, it remains active until changed.
///
/// # Example
///
/// ```rust
/// // test_utils feature required in dev-dependencies
/// use memalloc::{AllockedVec, AllockedVecBehaviour, AllockedVecError};
///
/// #[cfg(test)]
/// mod tests {
///     use super::*;
///
///     #[test]
///     fn test_handles_capacity_exceeded() -> Result<(), AllockedVecError> {
///         let mut vec = AllockedVec::with_capacity(10);
///
///         // Inject failure
///         vec.change_behaviour(AllockedVecBehaviour::FailAtPush);
///
///         // This will fail even though capacity allows it
///         let result = vec.push(1u8);
///         assert!(result.is_err());
///
///         // Reset to normal behaviour
///         vec.change_behaviour(AllockedVecBehaviour::None);
///
///         // Now it works
///         vec.push(1u8)?;
///         Ok(())
///     }
/// }
/// ```
#[cfg(any(test, feature = "test_utils"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllockedVecBehaviour {
    /// Normal behaviour - no injected failures.
    None,
    /// Next `push()` call will fail with `CapacityExceeded`.
    FailAtPush,
    /// Next `drain_from()` call will fail with `CapacityExceeded`.
    FailAtDrainFrom,
}

#[cfg(any(test, feature = "test_utils"))]
impl Default for AllockedVecBehaviour {
    fn default() -> Self {
        Self::None
    }
}

#[cfg(any(test, feature = "test_utils"))]
impl Zeroize for AllockedVecBehaviour {
    fn zeroize(&mut self) {
        *self = Self::None;
    }
}

#[cfg(any(test, feature = "test_utils"))]
impl memzer::ZeroizationProbe for AllockedVecBehaviour {
    fn is_zeroized(&self) -> bool {
        matches!(self, Self::None)
    }
}

#[cfg(any(test, feature = "test_utils"))]
impl memzer::Zeroizable for AllockedVecBehaviour {
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
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
/// use memalloc::{AllockedVec, AllockedVecError};
///
/// fn example() -> Result<(), AllockedVecError> {
///     let mut vec = AllockedVec::new();
///     vec.reserve_exact(5)?;
///
///     vec.push(1u8)?;
///     vec.push(2u8)?;
///
///     assert_eq!(vec.len(), 2);
///     assert_eq!(vec.capacity(), 5);
///     Ok(())
/// }
/// # example().unwrap();
/// ```
#[derive(Debug, Zeroize, MemZer)]
#[zeroize(drop)]
pub struct AllockedVec<T>
where
    T: Zeroize + ZeroizationProbe,
{
    inner: Vec<T>,
    has_been_sealed: bool,
    #[cfg(any(test, feature = "test_utils"))]
    behaviour: AllockedVecBehaviour,
    __drop_sentinel: DropSentinel,
}

impl<T> AllockedVec<T>
where
    T: Zeroize + ZeroizationProbe,
{
    pub(crate) fn realloc_with<F>(&mut self, capacity: usize, #[allow(unused)] mut hook: F)
    where
        T: Default + Zeroize,
        F: FnMut(&mut Self),
    {
        if capacity <= self.capacity() {
            return;
        }

        let new_allocked_vec = {
            let mut allocked_vec = AllockedVec::<T>::with_capacity(capacity);
            allocked_vec
                 .drain_from(self.as_mut_slice())
                 .expect("infallible: new vec len=0 prevents Overflow error (0 + len <= usize::MAX), and: capacity >
     self.capacity() >= self.len() implies that CapacityExceeded error is not possible.");
            allocked_vec
        };

        #[cfg(test)]
        hook(self);

        self.zeroize();

        #[cfg(test)]
        hook(self);

        *self = new_allocked_vec;
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
            #[cfg(any(test, feature = "test_utils"))]
            behaviour: AllockedVecBehaviour::default(),
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

        vec.reserve_exact(capacity)
            .expect("Infallible: Vec capacity is 0 (seal is false)");

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
    /// use memalloc::{AllockedVec, AllockedVecError};
    ///
    /// fn example() -> Result<(), AllockedVecError> {
    ///     let mut vec: AllockedVec<u8> = AllockedVec::new();
    ///     vec.reserve_exact(10)?;
    ///
    ///     // Second reserve fails
    ///     assert!(vec.reserve_exact(20).is_err());
    ///     Ok(())
    /// }
    /// # example().unwrap();
    /// ```
    pub fn reserve_exact(&mut self, capacity: usize) -> Result<(), AllockedVecError> {
        if self.has_been_sealed {
            return Err(AllockedVecError::AlreadySealed);
        }

        self.inner.reserve_exact(capacity);
        self.has_been_sealed = true;

        // When unsafe feature is enabled, zero the entire capacity to prevent
        // reading garbage via as_capacity_slice() / as_capacity_mut_slice()
        #[cfg(any(test, feature = "unsafe"))]
        if capacity > 0 {
            memutil::fast_zeroize_slice(self.as_capacity_mut_slice());
        }

        Ok(())
    }

    /// Pushes a value onto the end of the vector.
    ///
    /// # Errors
    ///
    /// Returns [`AllockedVecError::CapacityExceeded`] if the vector is at capacity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::{AllockedVec, AllockedVecError};
    ///
    /// fn example() -> Result<(), AllockedVecError> {
    ///     let mut vec = AllockedVec::with_capacity(2);
    ///     vec.push(1u8)?;
    ///     vec.push(2u8)?;
    ///
    ///     // Exceeds capacity
    ///     assert!(vec.push(3u8).is_err());
    ///     Ok(())
    /// }
    /// # example().unwrap();
    /// ```
    pub fn push(&mut self, value: T) -> Result<(), AllockedVecError> {
        #[cfg(any(test, feature = "test_utils"))]
        if matches!(self.behaviour, AllockedVecBehaviour::FailAtPush) {
            return Err(AllockedVecError::CapacityExceeded);
        }

        if self.len() >= self.capacity() {
            return Err(AllockedVecError::CapacityExceeded);
        }

        self.inner.push(value);
        Ok(())
    }

    /// Returns the number of elements in the vector.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::{AllockedVec, AllockedVecError};
    ///
    /// fn example() -> Result<(), AllockedVecError> {
    ///     let mut vec = AllockedVec::with_capacity(10);
    ///     vec.push(1u8)?;
    ///     assert_eq!(vec.len(), 1);
    ///     Ok(())
    /// }
    /// # example().unwrap();
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
    /// use memalloc::{AllockedVec, AllockedVecError};
    ///
    /// fn example() -> Result<(), AllockedVecError> {
    ///     let mut vec = AllockedVec::with_capacity(3);
    ///     vec.push(1u8)?;
    ///     vec.push(2u8)?;
    ///
    ///     assert_eq!(vec.as_slice(), &[1, 2]);
    ///     Ok(())
    /// }
    /// # example().unwrap();
    /// ```
    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    /// Returns a mutable slice view of the vector.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::{AllockedVec, AllockedVecError};
    ///
    /// fn example() -> Result<(), AllockedVecError> {
    ///     let mut vec = AllockedVec::with_capacity(3);
    ///     vec.push(1u8)?;
    ///     vec.push(2u8)?;
    ///
    ///     vec.as_mut_slice()[0] = 42;
    ///     assert_eq!(vec.as_slice(), &[42, 2]);
    ///     Ok(())
    /// }
    /// # example().unwrap();
    /// ```
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.inner
    }

    /// Truncates the vector to the specified length, zeroizing removed elements.
    ///
    /// If `new_len` is greater than or equal to the current length, this is a no-op.
    /// Otherwise, the elements beyond `new_len` are zeroized before truncation.
    ///
    /// # Security
    ///
    /// This method zeroizes removed elements before truncating to prevent sensitive
    /// data from remaining in spare capacity. A debug assertion verifies zeroization.
    ///
    /// # Note
    ///
    /// Unlike `Vec::truncate`, this method guarantees no data remains in spare capacity
    /// after the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::{AllockedVec, AllockedVecError};
    ///
    /// fn example() -> Result<(), AllockedVecError> {
    ///     let mut vec = AllockedVec::with_capacity(5);
    ///     vec.push(1u8)?;
    ///     vec.push(2u8)?;
    ///     vec.push(3u8)?;
    ///
    ///     vec.truncate(1);
    ///
    ///     assert_eq!(vec.len(), 1);
    ///     assert_eq!(vec.as_slice(), &[1]);
    ///     // Elements at indices 1 and 2 have been zeroized in spare capacity
    ///     Ok(())
    /// }
    /// # example().unwrap();
    /// ```
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.len() {
            self.inner[new_len..].iter_mut().zeroize();

            debug_assert!(
                self.inner[new_len..].iter().all(|v| v.is_zeroized()),
                "AllockedVec::truncate: zeroization failed"
            );

            self.inner.truncate(new_len);
        }
    }

    /// Drains values from a mutable slice into the vector.
    ///
    /// The source slice is zeroized after draining (each element replaced with `T::default()`).
    ///
    /// # Errors
    ///
    /// Returns [`AllockedVecError::CapacityExceeded`] if adding all elements would exceed capacity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::{AllockedVec, AllockedVecError};
    ///
    /// fn example() -> Result<(), AllockedVecError> {
    ///     let mut vec = AllockedVec::with_capacity(5);
    ///     let mut data = vec![1u8, 2, 3, 4, 5];
    ///
    ///     vec.drain_from(&mut data)?;
    ///
    ///     assert_eq!(vec.len(), 5);
    ///     assert!(data.iter().all(|&x| x == 0)); // Source zeroized
    ///     Ok(())
    /// }
    /// # example().unwrap();
    /// ```
    pub fn drain_from(&mut self, slice: &mut [T]) -> Result<(), AllockedVecError>
    where
        T: Default,
    {
        #[cfg(any(test, feature = "test_utils"))]
        if matches!(self.behaviour, AllockedVecBehaviour::FailAtDrainFrom) {
            return Err(AllockedVecError::CapacityExceeded);
        }

        // Note: checked_add overflow is practically impossible (requires len > isize::MAX),
        // but we keep this defensive check for integer overflow safety.
        let new_len = self
            .len()
            .checked_add(slice.len())
            .ok_or(AllockedVecError::Overflow)?;

        if new_len > self.capacity() {
            return Err(AllockedVecError::CapacityExceeded);
        }

        for item in slice.iter_mut() {
            let value = core::mem::take(item);
            self.inner.push(value);
        }

        Ok(())
    }

    /// Re-seals the vector with a new capacity, safely zeroizing the old allocation.
    ///
    /// This method allows expanding a sealed `AllockedVec` by:
    /// 1. Creating a new vector with the requested capacity
    /// 2. Draining data from the old vector to the new one (zeroizes source via `mem::take`)
    /// 3. Zeroizing the old vector (including spare capacity)
    /// 4. Replacing self with the new vector
    ///
    /// If `new_capacity <= current capacity`, this is a no-op.
    ///
    /// # Safety Guarantees
    ///
    /// - Old allocation is fully zeroized before being dropped
    /// - No unzeroized copies of data remain in memory
    /// - New allocation is sealed with the specified capacity
    ///
    /// # Example
    ///
    /// ```rust
    /// use memalloc::{AllockedVec, AllockedVecError};
    ///
    /// fn example() -> Result<(), AllockedVecError> {
    ///     let mut vec = AllockedVec::with_capacity(5);
    ///     vec.push(1u8)?;
    ///     vec.push(2u8)?;
    ///
    ///     // Expand capacity safely
    ///     vec.realloc_with_capacity(10);
    ///
    ///     // Now can push more elements
    ///     vec.push(3u8)?;
    ///     assert_eq!(vec.capacity(), 10);
    ///     Ok(())
    /// }
    /// # example().unwrap();
    /// ```
    pub fn realloc_with_capacity(&mut self, capacity: usize)
    where
        T: Default + Zeroize,
    {
        self.realloc_with(capacity, |_| {});
    }

    /// Changes the test behaviour for this vector.
    ///
    /// This is only available with the `test_utils` feature and allows injecting
    /// failures for testing error handling paths.
    ///
    /// # Example
    ///
    /// ```rust
    /// // test_utils feature required in dev-dependencies
    /// #[cfg(test)]
    /// mod tests {
    ///     use memalloc::{AllockedVec, AllockedVecBehaviour};
    ///
    ///     #[test]
    ///     fn test_error_handling() {
    ///         let mut vec = AllockedVec::with_capacity(10);
    ///         vec.change_behaviour(AllockedVecBehaviour::FailAtPush);
    ///
    ///         // Next push will fail
    ///         assert!(vec.push(1u8).is_err());
    ///     }
    /// }
    /// ```
    #[cfg(any(test, feature = "test_utils"))]
    pub fn change_behaviour(&mut self, behaviour: AllockedVecBehaviour) {
        self.behaviour = behaviour;
    }

    #[cfg(test)]
    pub(crate) fn __unsafe_expose_inner_for_tests<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Vec<T>),
    {
        f(&mut self.inner);
    }

    /// Returns a raw mutable pointer to the vector's buffer.
    ///
    /// # Safety
    ///
    /// This method is only available with the `unsafe` feature.
    #[cfg(any(test, feature = "unsafe"))]
    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.inner.as_mut_ptr()
    }

    /// Returns a slice of the full capacity, regardless of len.
    ///
    /// # Safety
    ///
    /// This method is only available with the `unsafe` feature.
    /// Bytes beyond `len()` may contain old data from previous operations.
    #[cfg(any(test, feature = "unsafe"))]
    #[inline(always)]
    pub fn as_capacity_slice(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.inner.as_ptr(), self.inner.capacity()) }
    }

    /// Returns a mutable slice of the full capacity, regardless of len.
    ///
    /// # Safety
    ///
    /// This method is only available with the `unsafe` feature.
    /// The caller must ensure writes don't exceed capacity.
    /// Bytes beyond `len()` may contain old data from previous operations.
    #[cfg(any(test, feature = "unsafe"))]
    #[inline(always)]
    pub fn as_capacity_mut_slice(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.inner.as_mut_ptr(), self.inner.capacity()) }
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
