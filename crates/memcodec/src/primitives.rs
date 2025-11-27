// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::{Zeroize, Zeroizing};

use crate::error::{DecodeBufferError, DecodeError};

use super::traits::{CodecBuffer, TryDecode};

// ============================================================================
// u8: No LE conversion needed, always bulk copy
// ============================================================================

impl TryDecode for u8 {
    #[inline(always)]
    fn try_decode_from(&mut self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.is_empty() {
            return Err(DecodeError::DecodeBufferError(
                DecodeBufferError::OutOfBounds,
            ));
        }

        *self = buf[0];
        Ok(())
    }
}

impl crate::traits::Encode for u8 {
    #[inline(always)]
    fn encode_into(
        &mut self,
        buf: &mut membuffer::Buffer,
    ) -> Result<(), crate::error::EncodeError> {
        buf.write(self)?;
        Ok(())
    }

    #[inline(always)]
    fn encode_slice_into(
        slice: &mut [Self],
        buf: &mut membuffer::Buffer,
    ) -> Result<(), crate::error::EncodeError> {
        buf.write_slice(slice)?;
        Ok(())
    }
}

impl crate::traits::BytesRequired for u8 {
    #[inline(always)]
    fn mem_bytes_required(&self) -> Result<usize, crate::error::OverflowError> {
        Ok(1)
    }
}

// For other primitives, on LE machines we can bulk copy (LE conversion is no-op)
// On BE machines, we fall back to element-by-element with conversion
macro_rules! impl_traits_for_primitives {
    ($($ty:ty),* $(,)?) => {
        $(
            impl $crate::traits::Encode for $ty {
                #[inline(always)]
                fn encode_into(&mut self, buf: &mut membuffer::Buffer) -> Result<(), $crate::error::EncodeError> {
                    // SECURITY NOTE: We extract bytes via bit-shifting instead of to_le()/swap_bytes()
                    // because those methods take `self` by value, potentially leaving copies on the stack.
                    //
                    // The shift operation `(*self >> (8 * i))` produces an intermediate value in a CPU
                    // register. This is unavoidable without inline assembly, but acceptable because:
                    // 1. Register values are ephemeral (nanoseconds) and constantly overwritten
                    // 2. There's no way to zeroize registers from Rust (compiler reordering, register
                    //    renaming, speculative execution make it unreliable even with asm)
                    // 3. The real leak risk is stack/heap memory, not registers
                    //
                    // What we DO guarantee:
                    // - `byte` is zeroized immediately after writing
                    // - `self` is zeroized after encoding completes
                    // - No copies persist in stack or heap memory
                    for i in 0..core::mem::size_of::<$ty>() {
                        let mut byte = zeroize::Zeroizing::new((*self >> (8 * i)) as u8);
                        buf.write(&mut byte)?;
                    }

                    #[cfg(feature = "zeroize")]
                    self.zeroize();

                    Ok(())
                }

                #[inline(always)]
                fn encode_slice_into(slice: &mut [Self], buf: &mut membuffer::Buffer) -> Result<(), $crate::error::EncodeError> {
                    #[cfg(target_endian = "little")]
                    {
                        // On LE machines, to_le is identity - bulk copy the bytes directly
                        let mut byte_len = slice.len() * core::mem::size_of::<$ty>();
                        let byte_slice = unsafe {
                            core::slice::from_raw_parts_mut(
                                slice.as_mut_ptr() as *mut u8,
                                byte_len
                            )
                        };

                        #[cfg(feature = "zeroize")]
                        byte_len.zeroize();

                        buf.write_slice(byte_slice)?;

                        #[cfg(feature = "zeroize")]
                        memutil::fast_zeroize_slice(byte_slice);

                        byte_len.zeroize();
                    }

                    #[cfg(target_endian = "big")]
                    {
                        // On BE machines, convert each element
                        for elem in slice.iter_mut() {
                            elem.encode_into(buf)?;
                        }
                    }
                    Ok(())
                }
            }

            impl $crate::traits::BytesRequired for $ty {
                #[inline(always)]
                fn mem_bytes_required(&self) -> Result<usize, $crate::error::OverflowError> {
                    Ok(core::mem::size_of::<$ty>())
                }
            }
        )*
    };
}

impl_traits_for_primitives!(u16, u32, u64, u128, usize);
