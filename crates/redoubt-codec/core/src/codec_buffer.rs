// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Secure buffer with locked capacity and automatic zeroization.
use alloc::vec::Vec;

use redoubt_alloc::AllockedVec;

#[cfg(feature = "zeroize")]
use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizeOnDropSentinel};

use crate::error::RedoubtCodecBufferError;

#[cfg_attr(feature = "zeroize", derive(RedoubtZero))]
pub struct RedoubtCodecBuffer {
    cursor: usize,
    capacity: usize,
    allocked_vec: AllockedVec<u8>,
    #[cfg(feature = "zeroize")]
    __sentinel: ZeroizeOnDropSentinel,
}

#[cfg(feature = "zeroize")]
impl Drop for RedoubtCodecBuffer {
    fn drop(&mut self) {
        self.fast_zeroize();
    }
}

impl Default for RedoubtCodecBuffer {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl RedoubtCodecBuffer {
    #[inline(always)]
    fn debug_assert_invariant(&self) {
        debug_assert!(
            self.cursor <= self.capacity,
            "Invariant violated: cursor ({}) <= capacity ({})",
            self.cursor,
            self.capacity
        );
    }

    #[inline(always)]
    pub fn with_capacity(capacity: usize) -> Self {
        let allocked_vec = AllockedVec::<u8>::with_capacity(capacity);

        Self {
            cursor: 0,
            capacity,
            allocked_vec,
            #[cfg(feature = "zeroize")]
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    #[inline(always)]
    pub fn realloc_with_capacity(&mut self, capacity: usize) {
        self.allocked_vec.realloc_with_capacity(capacity);
        self.allocked_vec.fill_with_default();

        self.capacity = capacity;
        self.cursor = 0;
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.cursor = 0;
        #[cfg(feature = "zeroize")]
        self.allocked_vec.fast_zeroize();
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { self.allocked_vec.as_capacity_slice() }
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { self.allocked_vec.as_capacity_mut_slice() }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        unsafe { self.allocked_vec.as_capacity_slice().len() }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline(always)]
    pub fn write<T>(&mut self, src: &mut T) -> Result<(), RedoubtCodecBufferError> {
        let len = core::mem::size_of::<T>();

        if self.cursor + len > self.capacity {
            return Err(RedoubtCodecBufferError::CapacityExceeded);
        }

        unsafe {
            let ptr = self.allocked_vec.as_mut_ptr().add(self.cursor);
            core::ptr::copy_nonoverlapping(src as *const T as *const u8, ptr, len);
        }
        self.cursor += len;

        // Invariant must be preserved before returning.
        self.debug_assert_invariant();

        Ok(())
    }

    #[inline(always)]
    pub fn write_slice<T>(&mut self, src: &mut [T]) -> Result<(), RedoubtCodecBufferError> {
        let byte_len = core::mem::size_of_val(src);

        if self.cursor + byte_len > self.capacity {
            return Err(RedoubtCodecBufferError::CapacityExceeded);
        }

        unsafe {
            let ptr = self.allocked_vec.as_mut_ptr().add(self.cursor);
            core::ptr::copy_nonoverlapping(src.as_ptr() as *const u8, ptr, byte_len);
        }
        self.cursor += byte_len;

        // Invariant must be preserved before returning.
        self.debug_assert_invariant();

        Ok(())
    }

    /// Exports the buffer contents as a `Vec<u8>` and zeroizes the internal buffer.
    ///
    /// This method creates a new `Vec` containing a copy of the buffer's data,
    /// then immediately zeroizes the internal buffer. The zeroization ensures
    /// that sensitive data is cleared from the `RedoubtCodecBuffer` after export,
    /// preventing potential memory leaks of plaintext data.
    ///
    /// # Security
    ///
    /// The zeroization happens **after** copying the data to the returned `Vec`,
    /// ensuring the internal buffer is always cleaned up when data is exported.
    /// This is crucial when the `RedoubtCodecBuffer` contains sensitive plaintext that
    /// should not remain in memory after encoding is complete.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut buf = RedoubtCodecBuffer::with_capacity(10);
    /// buf.write_usize(&42).unwrap();
    /// let exported = buf.export_as_vec();
    /// // buf is now zeroized, exported contains the data
    /// ```
    #[inline(always)]
    pub fn export_as_vec(&mut self) -> Vec<u8> {
        let vec = self.as_slice().to_vec();
        self.fast_zeroize();
        vec
    }
}
