// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memalloc::AllockedVec;
use memzer::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

use crate::wrappers::Primitive;

use crate::codec_buffer::CodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice, PreAlloc, TryDecode, TryEncode,
};

use super::helpers::{header_size, process_header, write_header};

/// Cleanup function for encode errors. Marked #[cold] to keep it out of the hot path.
#[cold]
#[inline(never)]
fn cleanup_encode_error<T>(vec: &mut AllockedVec<T>, buf: &mut CodecBuffer)
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    vec.fast_zeroize();
    buf.fast_zeroize();
}

/// Cleanup function for decode errors. Marked #[cold] to keep it out of the hot path.
#[cold]
#[inline(never)]
fn cleanup_decode_error<T>(vec: &mut AllockedVec<T>, buf: &mut &mut [u8])
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    vec.fast_zeroize();
    memutil::fast_zeroize_slice(*buf);
}

impl<T> BytesRequired for AllockedVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + BytesRequired + ZeroizationProbe,
{
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        let mut bytes_required = header_size();

        for elem in self.as_slice().iter() {
            let new_bytes_required = bytes_required.wrapping_add(elem.mem_bytes_required()?);

            if new_bytes_required < bytes_required {
                return Err(OverflowError {
                    reason: "AllockedVec bytes_required overflow".into(),
                });
            }

            bytes_required = new_bytes_required;
        }

        Ok(bytes_required)
    }
}

impl<T> TryEncode for AllockedVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + EncodeSlice + BytesRequired + ZeroizationProbe,
{
    fn try_encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let mut size = Primitive::new(self.len());
        let mut bytes_required = Primitive::new(self.mem_bytes_required()?);

        write_header(buf, &mut size, &mut bytes_required)?;

        T::encode_slice_into(self.as_mut_slice(), buf)
    }
}

impl<T> Encode for AllockedVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + EncodeSlice + BytesRequired + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let result = self.try_encode_into(buf);

        if result.is_err() {
            cleanup_encode_error(self, buf);
        } else {
            self.fast_zeroize();
        }

        result
    }
}

impl<T> EncodeSlice for AllockedVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + EncodeSlice + BytesRequired + ZeroizationProbe,
{
    fn encode_slice_into(slice: &mut [Self], buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        for elem in slice.iter_mut() {
            elem.encode_into(buf)?;
        }

        Ok(())
    }
}

impl<T> TryDecode for AllockedVec<T>
where
    T: DecodeSlice + FastZeroizable + ZeroizeMetadata + ZeroizationProbe + Default,
{
    #[inline(always)]
    fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let mut size = Primitive::new(0usize);

        process_header(buf, &mut size)?;

        self.prealloc(*size);

        T::decode_slice_from(self.as_mut_slice(), buf)
    }
}

impl<T> Decode for AllockedVec<T>
where
    T: DecodeSlice + FastZeroizable + ZeroizeMetadata + ZeroizationProbe + Default,
{
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let result = self.try_decode_from(buf);

        if result.is_err() {
            cleanup_decode_error(self, buf);
        }

        result
    }
}

impl<T> DecodeSlice for AllockedVec<T>
where
    T: DecodeSlice + FastZeroizable + ZeroizeMetadata + ZeroizationProbe + Default,
{
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for elem in slice.iter_mut() {
            elem.decode_from(buf)?;
        }

        Ok(())
    }
}

impl<T> PreAlloc for AllockedVec<T>
where
    T: FastZeroizable + ZeroizeMetadata + ZeroizationProbe + Default,
{
    const ZERO_INIT: bool = false;

    fn prealloc(&mut self, size: usize) {
        self.fast_zeroize();
        self.realloc_with_capacity(size);
        self.fill_with_default();

        unsafe {
            self.set_len(size);
        }

        debug_assert_eq!(self.len(), size);
    }
}

#[cfg(feature = "zeroize")]
#[inline(always)]
pub(crate) fn allocked_vec_codec_zeroize<T: ZeroizationProbe + FastZeroizable + ZeroizeMetadata>(
    vec: &mut AllockedVec<T>,
    _fast: bool,
) {
    // @TODO: use vec.zeroize() when the new crate is finished.
    for elem in vec.as_mut_slice() {
        elem.fast_zeroize();
    }
}
