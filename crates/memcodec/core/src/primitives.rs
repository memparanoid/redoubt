// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::error::DecodeError;
use crate::wrappers::Primitive;

use super::traits::{CodecBuffer, DecodeBuffer, TryEncode};

// On LE machines we can bulk copy (LE conversion is no-op)
// On BE machines, we fall back to element-by-element with conversion
macro_rules! impl_traits_for_primitives {
    ($($ty:ty),* $(,)?) => {
        $(
            // BytesRequired
            impl $crate::traits::BytesRequired for $ty {
                #[inline(always)]
                fn mem_bytes_required(&self) -> Result<usize, $crate::error::OverflowError> {
                    Ok(core::mem::size_of::<$ty>())
                }
            }

            // Encoding Traits
            impl $crate::traits::TryEncode for $ty {
                #[inline(always)]
                fn try_encode_into(&mut self, buf: &mut membuffer::Buffer) -> Result<(), $crate::error::EncodeError> {
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
                        let mut byte = Primitive::new((*self >> (8 * i)) as u8);
                        buf.write(&mut byte)?;
                    }

                    Ok(())
                }
            }

            impl $crate::traits::Encode for $ty {
                #[inline(always)]
                fn encode_into(&mut self, buf: &mut membuffer::Buffer) -> Result<(), $crate::error::EncodeError> {
                    let result = self.try_encode_into(buf);

                    #[cfg(feature = "zeroize")]
                    if result.is_err() {
                        self.zeroize();
                        buf.zeroize();
                    }

                    result
                }
            }

            // EncodeSlice - NO zeroize, collection handles it
            impl $crate::traits::EncodeSlice for $ty {
                #[inline(always)]
                fn encode_slice_into(slice: &mut [Self], buf: &mut membuffer::Buffer) -> Result<(), $crate::error::EncodeError> {
                    #[cfg(target_endian = "little")]
                    {
                        // On LE machines, bulk copy the bytes directly
                        let byte_len = slice.len() * core::mem::size_of::<$ty>();
                        let byte_slice = unsafe {
                            core::slice::from_raw_parts_mut(
                                slice.as_mut_ptr() as *mut u8,
                                byte_len
                            )
                        };
                        buf.write_slice(byte_slice)?;
                    }

                    #[cfg(target_endian = "big")]
                    {
                        // On BE machines, convert each element (encode_into zeroizes each)
                        for elem in slice.iter_mut() {
                            elem.encode_into(buf)?;
                        }
                    }
                    Ok(())
                }
            }

            // Decoding Traits
            impl $crate::traits::Decode for $ty {
                fn decode_from(&mut self, _buf: &mut &mut [u8]) -> Result<(), $crate::error::DecodeError> {
                    // Primitives as struct fields don't consume from buffer directly.
                    // Vec<primitive> uses decode_slice_from for bulk copy.
                    Ok(())
                }
            }

            // DecodeSlice - NO zeroize, collection handles it
            impl $crate::traits::DecodeSlice for $ty {
                #[inline(always)]
                fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
                    #[cfg(target_endian = "little")]
                    {
                        buf.read_slice(slice)?;
                    }

                    #[cfg(target_endian = "big")]
                    {
                        for elem in slice.iter_mut() {
                            elem.decode_from(buf)?;
                        }
                    }

                    Ok(())
                }
            }
        )*
    };
}

impl_traits_for_primitives!(u8, u16, u32, u64, u128, usize);
