// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use super::error::{CodecBufferError, DecodeBufferError};
use super::traits::{CodecBuffer, DecodeBuffer};

trait CodecBufferInvariant {
    fn debug_assert_invariant(&self);
}

impl CodecBufferInvariant for Buffer {
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
}

impl CodecBuffer for Buffer {
    fn write<T>(&mut self, src: &mut T) -> Result<(), CodecBufferError> {
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

    fn write_slice<T>(&mut self, src: &mut [T]) -> Result<(), CodecBufferError> {
        let byte_len = src.len() * core::mem::size_of::<T>();

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
}

impl DecodeBuffer for &mut [u8] {
    #[inline(always)]
    fn read_usize(&mut self, dst: &mut usize) -> Result<(), DecodeBufferError> {
        let size = core::mem::size_of::<usize>();

        if self.len() < size {
            return Err(DecodeBufferError::OutOfBounds);
        }

        // Native endian copy - no conversion
        unsafe {
            core::ptr::copy_nonoverlapping(self.as_ptr(), dst as *mut usize as *mut u8, size);
        }

        // Zeroize the Buffer
        #[cfg(feature = "zeroize")]
        memutil::fast_zeroize_slice(&mut self[..size]);

        // Shrink the slice - consume the bytes we read
        *self = &mut core::mem::take(self)[size..];

        Ok(())
    }

    #[inline(always)]
    fn read<T>(&mut self, dst: &mut T) -> Result<(), DecodeBufferError> {
        let len = core::mem::size_of::<T>();

        if self.len() < len {
            return Err(DecodeBufferError::OutOfBounds);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(self.as_ptr(), dst as *mut T as *mut u8, len);
        }

        // Zeroize the Buffer
        #[cfg(feature = "zeroize")]
        memutil::fast_zeroize_slice(&mut self[..len]);

        // Shrink the slice - consume the bytes we read
        *self = &mut core::mem::take(self)[len..];

        Ok(())
    }

    #[inline(always)]
    fn read_slice<T>(&mut self, dst: &mut [T]) -> Result<(), DecodeBufferError> {
        let byte_len = dst.len() * core::mem::size_of::<T>();

        if self.len() < byte_len {
            return Err(DecodeBufferError::OutOfBounds);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(self.as_ptr(), dst.as_mut_ptr() as *mut u8, byte_len);
        }

        // Zeroize the Buffer
        #[cfg(feature = "zeroize")]
        memutil::fast_zeroize_slice(&mut self[..byte_len]);

        // Shrink the slice
        *self = &mut core::mem::take(self)[byte_len..];

        Ok(())
    }
}
