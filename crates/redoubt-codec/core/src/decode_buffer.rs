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
        // SAFETY: the refusal above is what leaves the source at least `size`
        // bytes long, and the destination is one `usize`, which is that many.
        // `dst` is the caller's own value, not part of this slice.
        unsafe {
            redoubt_mem::copy_nonoverlapping(self.as_ptr(), dst as *mut usize as *mut u8, size);
        }

        // Zeroize the Buffer
        redoubt_util::fast_zeroize_slice(&mut self[..size]);

        // Shrink the slice - consume the bytes we read
        let mut taken = <&mut [u8]>::default();
        redoubt_mem::swap(self, &mut taken);
        *self = &mut taken[size..];

        Ok(())
    }

    #[inline(always)]
    fn read<T>(&mut self, dst: &mut T) -> Result<(), DecodeBufferError> {
        let len = core::mem::size_of::<T>();

        if self.len() < len {
            return Err(DecodeBufferError::OutOfBounds);
        }

        // SAFETY: the refusal above is what leaves the source at least `len`
        // bytes long, and `len` is the size of one `T`, which is what the
        // destination is. `dst` is the caller's own value, not part of this
        // slice.
        unsafe {
            redoubt_mem::copy_nonoverlapping(self.as_ptr(), dst as *mut T as *mut u8, len);
        }

        // Zeroize the Buffer
        redoubt_util::fast_zeroize_slice(&mut self[..len]);

        // Shrink the slice - consume the bytes we read
        let mut taken = <&mut [u8]>::default();
        redoubt_mem::swap(self, &mut taken);
        *self = &mut taken[len..];

        Ok(())
    }

    #[inline(always)]
    fn read_slice<T>(&mut self, dst: &mut [T]) -> Result<(), DecodeBufferError> {
        let byte_len = core::mem::size_of_val(dst);

        if self.len() < byte_len {
            return Err(DecodeBufferError::OutOfBounds);
        }

        // SAFETY: the refusal above is what leaves the source at least
        // `byte_len` bytes long, and `byte_len` is the destination's own size.
        // `dst` is the caller's own slice, not part of this one.
        unsafe {
            redoubt_mem::copy_nonoverlapping(self.as_ptr(), dst.as_mut_ptr() as *mut u8, byte_len);
        }

        // Zeroize the Buffer
        redoubt_util::fast_zeroize_slice(&mut self[..byte_len]);

        // Shrink the slice - consume the bytes we read
        let mut taken = <&mut [u8]>::default();
        redoubt_mem::swap(self, &mut taken);
        *self = &mut taken[byte_len..];

        Ok(())
    }
}
