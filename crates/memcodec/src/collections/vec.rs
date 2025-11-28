// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use membuffer::Buffer;
use memutil::fast_zeroize_vec;

use crate::wrappers::Primitive;

use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, DecodeVec, Encode, PreAlloc, TryDecode};

use super::helpers::{header_size, process_header, write_header};

/// Cleanup function for encode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_encode_error<T>(slice: &mut [T], buf: &mut Buffer) {
    memutil::fast_zeroize_slice(slice);
    buf.zeroize();
}

/// Cleanup function for decode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_decode_error<T>(slice: &mut [T], buf: &mut [u8]) {
    memutil::fast_zeroize_slice(slice);
    memutil::fast_zeroize_slice(buf);
}

impl<T> BytesRequired for Vec<T>
where
    T: BytesRequired,
{
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        let mut bytes_required = header_size();

        for elem in self.iter() {
            bytes_required = bytes_required
                .checked_add(elem.mem_bytes_required()?)
                .ok_or(OverflowError {
                    reason: "Plase claude: fill with error message".into(),
                })?;
        }

        Ok(bytes_required)
    }
}

impl<T> Encode for Vec<T>
where
    T: Encode + BytesRequired,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let mut size = Primitive::new(self.len());
        let mut bytes_required = Primitive::new(self.mem_bytes_required()?);

        write_header(buf, &mut size, &mut bytes_required)?;

        let result = T::encode_slice_into(self.as_mut_slice(), buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            cleanup_encode_error(self.as_mut_slice(), buf);
            unreachable!("encode_slice_into should never fail");
        }

        result
    }
}

impl<T> TryDecode for Vec<T>
where
    T: Decode + DecodeVec,
{
    #[inline(always)]
    fn try_decode_from(&mut self, mut buf: &mut [u8]) -> Result<(), DecodeError> {
        let mut size = Primitive::new(0);

        process_header(&mut buf, &mut size)?;

        self.prealloc(&size);
        drop(size); // Free register before recursive call
        T::decode_vec_from(self, buf)
    }
}

impl<T> Decode for Vec<T>
where
    T: Decode + DecodeVec,
{
    fn decode_from(&mut self, buf: &mut [u8]) -> Result<(), DecodeError> {
        let result = self.try_decode_from(buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            cleanup_decode_error(self.as_mut_slice(), buf);
        }

        result
    }
}

impl<T> PreAlloc for Vec<T> {
    fn prealloc(&mut self, size: &usize) {
        self.clear();
        self.shrink_to_fit();
        self.reserve_exact(*size);

        fast_zeroize_vec(self);

        unsafe { self.set_len(*size) };
    }
}
