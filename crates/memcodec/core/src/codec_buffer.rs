// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Secure buffer with locked capacity and automatic zeroization.
use memalloc::AllockedVec;
#[cfg(feature = "zeroize")]
use memzer::{
    AssertZeroizeOnDrop, DropSentinel, FastZeroizable, ZeroizationProbe, ZeroizeMetadata,
    assert::assert_zeroize_on_drop,
};

use crate::error::CodecBufferError;

pub struct CodecBuffer {
    pub ptr: *mut u8,
    pub end: *mut u8,
    pub cursor: *mut u8,
    allocked_vec: AllockedVec<u8>,
    #[cfg(feature = "zeroize")]
    __drop_sentinel: DropSentinel,
}

#[cfg(feature = "zeroize")]
impl Drop for CodecBuffer {
    fn drop(&mut self) {
        self.fast_zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl AssertZeroizeOnDrop for CodecBuffer {
    fn clone_drop_sentinel(&self) -> DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizationProbe for CodecBuffer {
    fn is_zeroized(&self) -> bool {
        self.ptr.is_null()
            & self.cursor.is_null()
            & self.allocked_vec.is_zeroized()
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeMetadata for CodecBuffer {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

#[cfg(feature = "zeroize")]
impl FastZeroizable for CodecBuffer {
    fn fast_zeroize(&mut self) {
        unsafe {
            core::ptr::write_volatile(&mut self.ptr, core::ptr::null_mut());
            core::ptr::write_volatile(&mut self.cursor, core::ptr::null_mut());
        }
        self.allocked_vec.fast_zeroize();
        self.__drop_sentinel.fast_zeroize();
    }
}

impl Default for CodecBuffer {
    fn default() -> Self {
        Self::new(0)
    }
}

impl CodecBuffer {
    #[inline(always)]
    fn debug_assert_invariant(&self) {
        debug_assert!(
            (self.ptr <= self.cursor) & (self.cursor <= self.end),
            "Invariant violated: ptr ({:p}) <= cursor ({:p}) <= end ({:p})",
            self.ptr,
            self.cursor,
            self.end
        );
    }

    #[inline(always)]
    pub fn new(capacity: usize) -> Self {
        let mut allocked_vec = AllockedVec::<u8>::with_capacity(capacity);

        let ptr = allocked_vec.as_mut_ptr();
        let end = unsafe { ptr.add(capacity) };
        let cursor = ptr;

        Self {
            ptr,
            end,
            cursor,
            allocked_vec,
            #[cfg(feature = "zeroize")]
            __drop_sentinel: DropSentinel::default(),
        }
    }

    #[inline(always)]
    pub fn realloc_with_capacity(&mut self, capacity: usize) {
        self.allocked_vec.realloc_with_capacity(capacity);
        self.allocked_vec.fill_with_default();

        self.ptr = self.allocked_vec.as_mut_ptr();
        self.end = unsafe { self.ptr.add(capacity) };
        self.cursor = self.ptr;
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.cursor = self.ptr;
        #[cfg(feature = "zeroize")]
        self.allocked_vec.fast_zeroize();
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        self.allocked_vec.as_capacity_slice()
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.allocked_vec.as_capacity_mut_slice()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.allocked_vec.as_capacity_slice().len()
    }

    #[inline(always)]
    pub fn write<T>(&mut self, src: &mut T) -> Result<(), CodecBufferError> {
        let len = core::mem::size_of::<T>();

        unsafe {
            if self.cursor.add(len) > self.end {
                return Err(CodecBufferError::CapacityExceeded);
            }

            core::ptr::copy_nonoverlapping(src as *const T as *const u8, self.cursor, len);
            self.cursor = self.cursor.add(len);
        }

        // Invariant must be preserved before returning.
        self.debug_assert_invariant();

        Ok(())
    }

    #[inline(always)]
    pub fn write_slice<T>(&mut self, src: &mut [T]) -> Result<(), CodecBufferError> {
        let byte_len = std::mem::size_of_val(src);

        unsafe {
            if self.cursor.add(byte_len) > self.end {
                return Err(CodecBufferError::CapacityExceeded);
            }

            core::ptr::copy_nonoverlapping(src.as_ptr() as *const u8, self.cursor, byte_len);
            self.cursor = self.cursor.add(byte_len);
        }

        // Invariant must be preserved before returning.
        self.debug_assert_invariant();

        Ok(())
    }

    /// Exports the buffer contents as a `Vec<u8>` and zeroizes the internal buffer.
    ///
    /// This method creates a new `Vec` containing a copy of the buffer's data,
    /// then immediately zeroizes the internal buffer. The zeroization ensures
    /// that sensitive data is cleared from the `CodecBuffer` after export,
    /// preventing potential memory leaks of plaintext data.
    ///
    /// # Security
    ///
    /// The zeroization happens **after** copying the data to the returned `Vec`,
    /// ensuring the internal buffer is always cleaned up when data is exported.
    /// This is crucial when the `CodecBuffer` contains sensitive plaintext that
    /// should not remain in memory after encoding is complete.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut buf = CodecBuffer::new(10);
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
