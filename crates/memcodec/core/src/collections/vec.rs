// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use membuffer::Buffer;

use crate::wrappers::Primitive;

use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, CodecZeroize, Decode, DecodeSlice, Encode, EncodeSlice, PreAlloc, TryDecode,
    TryEncode,
};

use super::helpers::{header_size, process_header, write_header};

/// Cleanup function for encode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_encode_error<T: CodecZeroize>(vec: &mut Vec<T>, buf: &mut Buffer) {
    vec.codec_zeroize();
    buf.zeroize();
}

/// Cleanup function for decode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_decode_error<T: CodecZeroize>(vec: &mut Vec<T>, buf: &mut &mut [u8]) {
    vec.codec_zeroize();
    memutil::fast_zeroize_slice(*buf);
}

impl<T> BytesRequired for Vec<T>
where
    T: BytesRequired,
{
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        let mut bytes_required = header_size();

        for elem in self.iter() {
            let new_bytes_required = bytes_required.wrapping_add(elem.mem_bytes_required()?);

            if new_bytes_required < bytes_required {
                return Err(OverflowError {
                    reason: "Vec::mem_bytes_required overflow".into(),
                });
            }

            bytes_required = new_bytes_required;
        }

        Ok(bytes_required)
    }
}

impl<T> TryEncode for Vec<T>
where
    T: EncodeSlice + BytesRequired + CodecZeroize,
{
    fn try_encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let mut size = Primitive::new(self.len());
        let mut bytes_required = Primitive::new(self.mem_bytes_required()?);

        write_header(buf, &mut size, &mut bytes_required)?;

        T::encode_slice_into(self.as_mut_slice(), buf)
    }
}

impl<T> Encode for Vec<T>
where
    T: EncodeSlice + BytesRequired + CodecZeroize,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let result = self.try_encode_into(buf);

        #[cfg(feature = "zeroize")]
        {
            if result.is_err() {
                cleanup_encode_error(self, buf);
            } else {
                self.codec_zeroize();
            }
        }

        result
    }
}

impl<T> EncodeSlice for Vec<T>
where
    T: EncodeSlice + BytesRequired + CodecZeroize,
{
    fn encode_slice_into(slice: &mut [Self], buf: &mut Buffer) -> Result<(), EncodeError> {
        for elem in slice.iter_mut() {
            elem.encode_into(buf)?;
        }

        Ok(())
    }
}

impl<T> TryDecode for Vec<T>
where
    T: DecodeSlice + PreAlloc + CodecZeroize,
{
    #[inline(always)]
    fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let mut size = Primitive::new(0);

        process_header(buf, &mut size)?;

        self.prealloc(*size);

        T::decode_slice_from(self.as_mut_slice(), buf)
    }
}

impl<T> Decode for Vec<T>
where
    T: DecodeSlice + PreAlloc + CodecZeroize,
{
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let result = self.try_decode_from(buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            cleanup_decode_error(self, buf);
        }

        result
    }
}

impl<T> DecodeSlice for Vec<T>
where
    T: DecodeSlice + PreAlloc + CodecZeroize,
{
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for elem in slice.iter_mut() {
            elem.decode_from(buf)?;
        }

        Ok(())
    }
}

impl<T: PreAlloc> PreAlloc for Vec<T> {
    /// Vec can NEVER be zero-initialized (has ptr/len/capacity).
    const ZERO_INIT: bool = false;

    fn prealloc(&mut self, size: usize) {
        self.clear();
        if T::ZERO_INIT {
            self.shrink_to_fit();
            self.reserve_exact(size);
            memutil::fast_zeroize_vec(self);
            unsafe { self.set_len(size) };
        } else {
            self.resize_with(size, Default::default);
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T: CodecZeroize> CodecZeroize for Vec<T> {
    /// Vec can NEVER be fast-zeroized from outside (has ptr/len/capacity).
    const FAST_ZEROIZE: bool = false;

    fn codec_zeroize(&mut self) {
        if T::FAST_ZEROIZE {
            // T is a primitive - memset entire allocation (contents + spare capacity)
            memutil::fast_zeroize_vec(self);
        } else {
            // T is complex - recurse into each element first
            for elem in self.iter_mut() {
                elem.codec_zeroize();
            }
            // Then zeroize spare capacity
            memutil::zeroize_spare_capacity(self);
        }
    }
}
