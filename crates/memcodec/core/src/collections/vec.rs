// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::codec_buffer::CodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice, FastZeroizable, PreAlloc, TryDecode,
    TryEncode, ZeroizeMetadata,
};
use crate::wrappers::Primitive;

use super::helpers::{header_size, process_header, write_header};

/// Cleanup function for encode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_encode_error<T: FastZeroizable + ZeroizeMetadata>(vec: &mut Vec<T>, buf: &mut CodecBuffer) {
    vec.fast_zeroize();
    buf.zeroize();
}

/// Cleanup function for decode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_decode_error<T: FastZeroizable + ZeroizeMetadata>(vec: &mut Vec<T>, buf: &mut &mut [u8]) {
    vec.fast_zeroize();
    buf.zeroize();
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
    T: EncodeSlice + BytesRequired + FastZeroizable + ZeroizeMetadata,
{
    fn try_encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let mut size = Primitive::new(self.len());
        let mut bytes_required = Primitive::new(self.mem_bytes_required()?);

        write_header(buf, &mut size, &mut bytes_required)?;

        T::encode_slice_into(self.as_mut_slice(), buf)
    }
}

impl<T> Encode for Vec<T>
where
    T: EncodeSlice + BytesRequired + FastZeroizable + ZeroizeMetadata,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let result = self.try_encode_into(buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            cleanup_encode_error(self, buf);
        }

        result
    }
}

impl<T> EncodeSlice for Vec<T>
where
    T: EncodeSlice + BytesRequired + FastZeroizable + ZeroizeMetadata,
{
    fn encode_slice_into(slice: &mut [Self], buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        for elem in slice.iter_mut() {
            elem.encode_into(buf)?;
        }

        Ok(())
    }
}

impl<T> TryDecode for Vec<T>
where
    T: DecodeSlice + PreAlloc + FastZeroizable + ZeroizeMetadata,
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
    T: DecodeSlice + PreAlloc + FastZeroizable + ZeroizeMetadata,
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
    T: DecodeSlice + PreAlloc + FastZeroizable + ZeroizeMetadata,
{
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for elem in slice.iter_mut() {
            elem.decode_from(buf)?;
        }

        Ok(())
    }
}

#[inline(always)]
pub(crate) fn vec_prealloc<T: PreAlloc + FastZeroizable + ZeroizeMetadata>(
    vec: &mut Vec<T>,
    size: usize,
    zero_init: bool,
) {
    vec.fast_zeroize();

    if zero_init {
        vec.shrink_to_fit();
        vec.reserve_exact(size);
        memutil::fast_zeroize_vec(vec);

        unsafe { vec.set_len(size) };
    } else {
        vec.resize_with(size, Default::default);
    }
}

impl<T: PreAlloc + FastZeroizable + ZeroizeMetadata> PreAlloc for Vec<T> {
    /// Vec can NEVER be zero-initialized (has ptr/len/capacity).
    const ZERO_INIT: bool = false;

    fn prealloc(&mut self, size: usize) {
        vec_prealloc(self, size, T::ZERO_INIT);
    }
}

#[cfg(feature = "zeroize")]
#[inline(always)]
pub(crate) fn vec_codec_zeroize<T: FastZeroizable + ZeroizeMetadata>(vec: &mut Vec<T>, fast: bool) {
    if fast {
        // T is a primitive - memset entire allocation (contents + spare capacity)
        memutil::fast_zeroize_vec(vec);
    } else {
        // T is complex - recurse into each element first
        for elem in vec.iter_mut() {
            elem.fast_zeroize();
        }
        // Then zeroize spare capacity
        memutil::zeroize_spare_capacity(vec);
    }
}

