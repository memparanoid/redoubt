// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::codec_buffer::CodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice, FastZeroizable, TryDecode, TryEncode,
    ZeroizeMetadata,
};
use crate::wrappers::Primitive;

use super::helpers::{header_size, process_header, write_header};

/// Cleanup function for encode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_encode_error<T: FastZeroizable + ZeroizeMetadata, const N: usize>(
    arr: &mut [T; N],
    buf: &mut CodecBuffer,
) {
    arr.fast_zeroize();
    buf.zeroize();
}

/// Cleanup function for decode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_decode_error<T: FastZeroizable + ZeroizeMetadata, const N: usize>(
    arr: &mut [T; N],
    buf: &mut &mut [u8],
) {
    arr.fast_zeroize();
    memutil::fast_zeroize_slice(*buf);
}

impl<T, const N: usize> BytesRequired for [T; N]
where
    T: BytesRequired,
{
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        let mut bytes_required = header_size();

        for elem in self.iter() {
            let new_bytes_required = bytes_required.wrapping_add(elem.mem_bytes_required()?);

            if new_bytes_required < bytes_required {
                return Err(OverflowError {
                    reason: "Array bytes_required overflow".into(),
                });
            }

            bytes_required = new_bytes_required;
        }

        Ok(bytes_required)
    }
}

impl<T, const N: usize> TryEncode for [T; N]
where
    T: EncodeSlice + BytesRequired + FastZeroizable + ZeroizeMetadata,
{
    fn try_encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let mut size = Primitive::new(N);
        let mut bytes_required = Primitive::new(self.mem_bytes_required()?);

        write_header(buf, &mut size, &mut bytes_required)?;

        T::encode_slice_into(self.as_mut_slice(), buf)
    }
}

impl<T, const N: usize> Encode for [T; N]
where
    T: EncodeSlice + BytesRequired + FastZeroizable + ZeroizeMetadata,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let result = self.try_encode_into(buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            cleanup_encode_error(self, buf);
        } else {
            self.fast_zeroize();
        }

        result
    }
}

impl<T, const N: usize> EncodeSlice for [T; N]
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

impl<T, const N: usize> TryDecode for [T; N]
where
    T: DecodeSlice + FastZeroizable + ZeroizeMetadata,
{
    #[inline(always)]
    fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let mut size = Primitive::new(0usize);

        process_header(buf, &mut size)?;

        // Validate that encoded size matches array size
        if *size != N {
            return Err(DecodeError::PreconditionViolated);
        }

        drop(size);

        T::decode_slice_from(self.as_mut_slice(), buf)
    }
}

impl<T, const N: usize> Decode for [T; N]
where
    T: DecodeSlice + FastZeroizable + ZeroizeMetadata,
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

impl<T, const N: usize> DecodeSlice for [T; N]
where
    T: DecodeSlice + FastZeroizable + ZeroizeMetadata,
{
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for elem in slice.iter_mut() {
            elem.decode_from(buf)?;
        }

        Ok(())
    }
}

// PreAlloc for arrays - allows arrays to be used as Vec elements
// Note: [T; N]: Default only works for N <= 32 in stable Rust
use crate::traits::PreAlloc;

impl<T: Default, const N: usize> PreAlloc for [T; N]
where
    Self: Default,
{
    /// Arrays cannot be zero-initialized (must use Default::default() for proper initialization)
    const ZERO_INIT: bool = false;

    fn prealloc(&mut self, _size: usize) {
        // Arrays are fixed-size, nothing to preallocate
    }
}

#[cfg(feature = "zeroize")]
#[inline(always)]
pub(crate) fn array_codec_zeroize<T: FastZeroizable + ZeroizeMetadata, const N: usize>(
    arr: &mut [T; N],
    fast: bool,
) {
    if fast {
        // T is a primitive - memset the whole array
        memutil::fast_zeroize_slice(arr.as_mut_slice());
    } else {
        // T is complex - recurse into each element
        for elem in arr.iter_mut() {
            elem.fast_zeroize();
        }
    }
}
