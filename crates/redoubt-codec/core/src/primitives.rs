// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};

use super::traits::{
    BytesRequired, Decode, DecodeBuffer, DecodeSlice, Encode, EncodeSlice, PreAlloc, TryDecode,
    TryEncode,
};

// Native endian - bulk copy for all architectures
macro_rules! impl_traits_for_primitives {
    ($($ty:ty),* $(,)?) => {
        $(
            impl $crate::traits::BytesRequired for $ty {
                #[inline(always)]
                fn encode_bytes_required(&self) -> Result<usize, $crate::error::OverflowError> {
                    Ok(core::mem::size_of::<$ty>())
                }
            }

            impl $crate::traits::TryEncode for $ty {
                #[inline(always)]
                fn try_encode_into(&mut self, buf: &mut $crate::codec_buffer::RedoubtCodecBuffer) -> Result<(), $crate::error::EncodeError> {
                    buf.write(self)?;
                    Ok(())
                }
            }

            impl $crate::traits::Encode for $ty {
                #[inline(always)]
                fn encode_into(&mut self, buf: &mut $crate::codec_buffer::RedoubtCodecBuffer) -> Result<(), $crate::error::EncodeError> {
                    let result = self.try_encode_into(buf);

                    self.fast_zeroize();

                    if result.is_err() {
                        buf.fast_zeroize();
                    }

                    result
                }
            }

            /// Caller is responsible for zeroizing slice and buffer on error.
            impl $crate::traits::EncodeSlice for $ty {
                #[inline(always)]
                fn encode_slice_into(slice: &mut [Self], buf: &mut $crate::codec_buffer::RedoubtCodecBuffer) -> Result<(), $crate::error::EncodeError> {
                    buf.write_slice(slice)?;
                    Ok(())
                }
            }

            impl $crate::traits::TryDecode for $ty {
                #[inline(always)]
                fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), $crate::error::DecodeError> {
                    buf.read(self)?;
                    Ok(())
                }
            }

            impl $crate::traits::Decode for $ty {
                #[inline(always)]
                fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), $crate::error::DecodeError> {
                    let result = self.try_decode_from(buf);

                    if result.is_err() {
                        self.fast_zeroize();
                        buf.fast_zeroize();
                    }

                    result
                }
            }

            /// Caller is responsible for zeroizing slice and buffer on error.
            impl $crate::traits::DecodeSlice for $ty {
                #[inline(always)]
                fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
                    buf.read_slice(slice)?;
                    Ok(())
                }
            }

            impl $crate::traits::PreAlloc for $ty {
                const ZERO_INIT: bool = true;

                #[inline(always)]
                fn prealloc(&mut self, _size: usize) {
                    // No-op: collection must preallocate memory with zeroes
                }
            }
        )*
    };
}

// No `usize` or `isize`: what they encode is `size_of` bytes of native memory,
// which is four on `wasm32` and eight on `x86_64`. A field that has to cross
// between them says `u64` or `i64` and means it.
//
// No `bool` either: the macro copies bytes both ways, and a byte that is
// neither zero nor one read back as a `bool` is undefined rather than an
// error. It travels as a `u8` below, and comes back through a match.
impl_traits_for_primitives!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64,);

impl BytesRequired for bool {
    #[inline(always)]
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        Ok(core::mem::size_of::<u8>())
    }
}

impl TryEncode for bool {
    #[inline(always)]
    fn try_encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        buf.write(&mut u8::from(*self))?;

        Ok(())
    }
}

impl Encode for bool {
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        let result = self.try_encode_into(buf);

        self.fast_zeroize();

        if result.is_err() {
            buf.fast_zeroize();
        }

        result
    }
}

/// Caller is responsible for zeroizing slice and buffer on error.
impl EncodeSlice for bool {
    #[inline(always)]
    fn encode_slice_into(
        slice: &mut [Self],
        buf: &mut RedoubtCodecBuffer,
    ) -> Result<(), EncodeError> {
        for value in slice.iter_mut() {
            buf.write(&mut u8::from(*value))?;
        }

        Ok(())
    }
}

impl TryDecode for bool {
    #[inline(always)]
    fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let mut byte = 0_u8;

        buf.read(&mut byte)?;
        *self = decoded_bool(byte)?;

        Ok(())
    }
}

impl Decode for bool {
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let result = self.try_decode_from(buf);

        if result.is_err() {
            self.fast_zeroize();
            buf.fast_zeroize();
        }

        result
    }
}

/// Caller is responsible for zeroizing slice and buffer on error.
impl DecodeSlice for bool {
    #[inline(always)]
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for value in slice.iter_mut() {
            let mut byte = 0_u8;

            buf.read(&mut byte)?;
            *value = decoded_bool(byte)?;
        }

        Ok(())
    }
}

impl PreAlloc for bool {
    const ZERO_INIT: bool = true;

    #[inline(always)]
    fn prealloc(&mut self, _size: usize) {
        // No-op: collection must preallocate memory with zeroes
    }
}

#[inline(always)]
fn decoded_bool(byte: u8) -> Result<bool, DecodeError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::PreconditionViolated),
    }
}
