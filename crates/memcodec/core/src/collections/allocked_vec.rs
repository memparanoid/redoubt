// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use memalloc::AllockedVec;
use membuffer::Buffer;
use memzer::ZeroizationProbe;

use crate::wrappers::Primitive;

use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice, PreAlloc, TryDecode, TryEncode,
};

use super::helpers::{header_size, process_header, write_header};

/// Cleanup function for encode errors. Marked #[cold] to keep it out of the hot path.
#[cold]
#[inline(never)]
fn cleanup_encode_error<T>(vec: &mut AllockedVec<T>, buf: &mut Buffer)
where
    T: Zeroize + ZeroizationProbe,
{
    vec.zeroize();
    buf.zeroize();
}

/// Cleanup function for decode errors. Marked #[cold] to keep it out of the hot path.
#[cold]
#[inline(never)]
fn cleanup_decode_error<T>(vec: &mut AllockedVec<T>, buf: &mut &mut [u8])
where
    T: Zeroize + ZeroizationProbe,
{
    vec.zeroize();
    memutil::fast_zeroize_slice(*buf);
}

impl<T> BytesRequired for AllockedVec<T>
where
    T: BytesRequired + Zeroize + ZeroizationProbe,
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
    T: EncodeSlice + BytesRequired + Zeroize + ZeroizationProbe,
{
    fn try_encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let mut size = Primitive::new(self.len());
        let mut bytes_required = Primitive::new(self.mem_bytes_required()?);

        write_header(buf, &mut size, &mut bytes_required)?;

        T::encode_slice_into(self.as_mut_slice(), buf)
    }
}

impl<T> Encode for AllockedVec<T>
where
    T: EncodeSlice + BytesRequired + Zeroize + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let result = self.try_encode_into(buf);

        if result.is_err() {
            cleanup_encode_error(self, buf);
        } else {
            self.zeroize();
        }

        result
    }
}

impl<T> EncodeSlice for AllockedVec<T>
where
    T: EncodeSlice + BytesRequired + Zeroize + ZeroizationProbe,
{
    fn encode_slice_into(slice: &mut [Self], buf: &mut Buffer) -> Result<(), EncodeError> {
        for elem in slice.iter_mut() {
            elem.encode_into(buf)?;
        }

        Ok(())
    }
}

impl<T> TryDecode for AllockedVec<T>
where
    T: DecodeSlice + Zeroize + ZeroizationProbe + Default,
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
    T: DecodeSlice + Zeroize + ZeroizationProbe + Default,
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
    T: DecodeSlice + Zeroize + ZeroizationProbe + Default,
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
    T: Zeroize + ZeroizationProbe + Default,
{
    fn prealloc(&mut self, size: usize) {
        self.zeroize();

        *self = AllockedVec::with_capacity(size);
        self.fill_with_default();

        debug_assert_eq!(self.len(), size);
    }
}
