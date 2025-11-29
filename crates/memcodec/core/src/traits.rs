// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use membuffer::Buffer;

use crate::error::{CodecBufferError, DecodeBufferError, DecodeError, EncodeError, OverflowError};

pub trait BytesRequired {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError>;
}

pub trait Encode {
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError>;

    /// Drain a slice of Self into the buffer.
    /// Default implementation: loop and call drain_into on each collection.
    /// This is ONLY used in nested collections.
    /// Primitives override this with bulk copy for performance.
    fn encode_slice_into(slice: &mut [Self], buf: &mut Buffer) -> Result<(), EncodeError>
    where
        Self: Sized,
    {
        for elem in slice.iter_mut() {
            let result = elem.encode_into(buf);

            if result.is_err() {
                #[cfg(feature = "zeroize")]
                {
                    memutil::fast_zeroize_slice(slice);
                    buf.zeroize();
                }

                return result;
            }
        }

        Ok(())
    }
}

// @TODO: Doc why this trait is useful
pub(crate) trait TryDecode {
    fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError>;
}

pub trait Decode {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError>;
}

// pub(crate) trait DecodeSlice: Decode {
//     /// Decode a slice of Self from the buffer.
//     /// Default implementation: loop and call drain_into on each collection.
//     /// This is ONLY used in nested collections.
//     /// Primitives override this with bulk copy for performance.
//     fn decode_slice_from(slice: &mut [Self], buf: &mut [u8]) -> Result<(), DecodeError>
//     where
//         Self: Sized,
//     {
//         for elem in slice.iter_mut() {
//             let result = elem.decode_from(buf);

//             if result.is_err() {
//                 #[cfg(feature = "zeroize")]
//                 {
//                     memutil::fast_zeroize_slice(slice);
//                     buf.zeroize();
//                 }

//                 return result;
//             }
//         }

//         Ok(())
//     }
// }

// @TODO: Doc why this trait is useful
pub(crate) trait TryDecodeVec: Sized {
    fn try_decode_vec_from(vec: &mut Vec<Self>, buf: &mut &mut [u8]) -> Result<(), DecodeError>;
}

pub(crate) trait DecodeVec: Decode + Sized {
    /// Decode a Vec of Self from the buffer.
    /// Default implementation: loop and call decode_from on each element.
    /// This is ONLY used in nested collections.
    /// Primitives override this with bulk copy for performance.
    fn decode_vec_from(vec: &mut Vec<Self>, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for elem in vec.iter_mut() {
            let result = elem.decode_from(buf);

            if result.is_err() {
                #[cfg(feature = "zeroize")]
                {
                    memutil::fast_zeroize_vec(vec);
                    (*buf).zeroize();
                }

                return result;
            }
        }

        Ok(())
    }
}

pub trait CodecBuffer {
    fn write<T>(&mut self, src: &mut T) -> Result<(), CodecBufferError>;
    fn write_slice(&mut self, src: &mut [u8]) -> Result<(), CodecBufferError>;
}

pub trait DecodeBuffer {
    fn read_usize(&mut self, dst: &mut usize) -> Result<(), DecodeBufferError>;
    fn read<T>(&mut self, dst: &mut T) -> Result<(), DecodeBufferError>;
    fn read_slice<T>(&mut self, dst: &mut [T], len: usize) -> Result<(), DecodeBufferError>;
}

pub(crate) trait PreAlloc {
    fn prealloc(&mut self, size: &usize);
}
