// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use memzer::FastZeroizable;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::error::DecodeError;

use super::traits::{DecodeBuffer, TryDecode, TryEncode};

// Native endian - bulk copy for all architectures
macro_rules! impl_traits_for_primitives {
    ($($ty:ty),* $(,)?) => {
        $(
            impl $crate::traits::BytesRequired for $ty {
                #[inline(always)]
                fn mem_bytes_required(&self) -> Result<usize, $crate::error::OverflowError> {
                    Ok(core::mem::size_of::<$ty>())
                }
            }

            impl $crate::traits::TryEncode for $ty {
                #[inline(always)]
                fn try_encode_into(&mut self, buf: &mut $crate::codec_buffer::CodecBuffer) -> Result<(), $crate::error::EncodeError> {
                    buf.write(self)?;
                    Ok(())
                }
            }

            impl $crate::traits::Encode for $ty {
                #[inline(always)]
                fn encode_into(&mut self, buf: &mut $crate::codec_buffer::CodecBuffer) -> Result<(), $crate::error::EncodeError> {
                    let result = self.try_encode_into(buf);

                    #[cfg(feature = "zeroize")]
                    self.zeroize();

                    #[cfg(feature = "zeroize")]
                    if result.is_err() {
                        buf.fast_zeroize();
                    }

                    result
                }
            }

            /// Caller is responsible for zeroizing slice and buffer on error.
            impl $crate::traits::EncodeSlice for $ty {
                #[inline(always)]
                fn encode_slice_into(slice: &mut [Self], buf: &mut $crate::codec_buffer::CodecBuffer) -> Result<(), $crate::error::EncodeError> {
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

                    #[cfg(feature = "zeroize")]
                    if result.is_err() {
                        self.zeroize();
                        buf.zeroize();
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

impl_traits_for_primitives!(
    bool, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64,
);
