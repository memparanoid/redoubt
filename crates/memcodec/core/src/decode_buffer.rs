// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::error::DecodeBufferError;
use super::traits::DecodeBuffer;

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
        let byte_len = std::mem::size_of_val(dst);

        if self.len() < byte_len {
            return Err(DecodeBufferError::OutOfBounds);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(self.as_ptr(), dst.as_mut_ptr() as *mut u8, byte_len);
        }

        // Zeroize the Buffer
        #[cfg(feature = "zeroize")]
        memutil::fast_zeroize_slice(&mut self[..byte_len]);

        // Shrink the slice - consume the bytes we read
        *self = &mut core::mem::take(self)[byte_len..];

        Ok(())
    }
}
