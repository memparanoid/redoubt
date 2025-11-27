// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use membuffer::Buffer;
use zeroize::Zeroizing;

use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, DecodeVec, Encode, PreAlloc, TryDecode};

use super::helpers::{header_size, process_header, write_header};

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
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let mut size = Zeroizing::new(self.len());
        let mut bytes_required = Zeroizing::new(self.mem_bytes_required()?);

        write_header(buf, &mut size, &mut bytes_required)?;

        // Use drain_slice_into - primitives will bulk copy, complex types loop
        let result = T::encode_slice_into(self.as_mut_slice(), buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            memutil::fast_zeroize_slice(self.as_mut_slice());
            buf.zeroize();
        }

        result
    }
}

impl<T> TryDecode for Vec<T>
where
    T: Decode + DecodeVec,
{
    fn try_decode_from(&mut self, mut buf: &mut [u8]) -> Result<(), DecodeError> {
        let mut size = Zeroizing::new(0);
        let mut bytes_required = Zeroizing::new(0);

        process_header(&mut buf, &mut size, &mut bytes_required)?;

        if buf.len() < *bytes_required {
            return Err(DecodeError::PreconditionViolated);
        }

        self.prealloc(&size);
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
            memutil::fast_zeroize_slice(self.as_mut_slice());
            memutil::fast_zeroize_slice(buf);
        }

        result
    }
}

impl<T> PreAlloc for Vec<T> {
    fn prealloc(&mut self, size: &usize) {
        self.clear();
        self.shrink_to_fit();
        self.reserve_exact(*size);
    }
}
