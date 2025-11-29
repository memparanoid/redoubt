// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use membuffer::Buffer;

use crate::wrappers::Primitive;

use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, Decode, DecodeVec, Encode, EncodeSlice, PreAlloc, TryDecode, TryEncode,
};

use super::helpers::{header_size, process_header, write_header};

/// Cleanup function for encode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_encode_error<T>(vec: &mut Vec<T>, buf: &mut Buffer) {
    memutil::fast_zeroize_vec(vec);
    buf.zeroize();
}

/// Cleanup function for decode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_decode_error<T>(vec: &mut Vec<T>, buf: &mut &mut [u8]) {
    memutil::fast_zeroize_vec(vec);
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
                    reason: "Plase claude: fill with error message".into(),
                });
            }

            bytes_required = new_bytes_required;
        }

        Ok(bytes_required)
    }
}

impl<T> TryEncode for Vec<T>
where
    T: EncodeSlice + BytesRequired,
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
    T: EncodeSlice + BytesRequired,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let result = self.try_encode_into(buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            cleanup_encode_error(self, buf);
        } else {
            memutil::fast_zeroize_vec(self);
        }

        result
    }
}

impl<T> EncodeSlice for Vec<T>
where
    T: EncodeSlice + BytesRequired,
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
    T: Decode + DecodeVec,
{
    #[inline(always)]
    fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let mut size = Primitive::new(0);

        process_header(buf, &mut size)?;

        self.prealloc(&size);
        drop(size); // Free register before recursive call
        T::decode_vec_from(self, buf)
    }
}

impl<T> Decode for Vec<T>
where
    T: Decode + DecodeVec,
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

impl<T> PreAlloc for Vec<T> {
    fn prealloc(&mut self, size: &usize) {
        self.clear();
        self.shrink_to_fit();
        self.reserve_exact(*size);

        memutil::fast_zeroize_vec(self);

        unsafe { self.set_len(*size) };
    }
}
