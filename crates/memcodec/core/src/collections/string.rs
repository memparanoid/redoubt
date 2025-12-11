// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use memzer::FastZeroizable;

use crate::codec_buffer::CodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice, PreAlloc, TryDecode, TryEncode,
};
use crate::zeroizing::Zeroizing;

use super::helpers::{header_size, process_header, write_header};

/// Cleanup function for encode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_encode_error(s: &mut String, buf: &mut CodecBuffer) {
    s.fast_zeroize();
    buf.fast_zeroize();
}

/// Cleanup function for decode errors. Marked #[cold] to keep it out of the hot path.
#[cfg(feature = "zeroize")]
#[cold]
#[inline(never)]
fn cleanup_decode_error(s: &mut String, buf: &mut &mut [u8]) {
    // SAFETY: We're zeroizing and then clearing, so UTF-8 invariant is restored
    unsafe {
        memutil::fast_zeroize_slice(s.as_bytes_mut());
    }
    s.clear();
    memutil::fast_zeroize_slice(*buf);
}

#[inline(always)]
pub(crate) fn string_bytes_required(len: usize) -> Result<usize, OverflowError> {
    let bytes_required = header_size().wrapping_add(len);

    if bytes_required < header_size() {
        return Err(OverflowError {
            reason: "String bytes_required overflow".into(),
        });
    }

    Ok(bytes_required)
}

impl BytesRequired for String {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        string_bytes_required(self.len())
    }
}

impl TryEncode for String {
    fn try_encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let mut bytes_required = Zeroizing::from(&mut self.mem_bytes_required()?);
        let mut size = Zeroizing::from(&mut self.len());

        write_header(buf, &mut size, &mut bytes_required)?;

        let bytes = unsafe { self.as_bytes_mut() };
        u8::encode_slice_into(bytes, buf)
    }
}

impl Encode for String {
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        let result = self.try_encode_into(buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            cleanup_encode_error(self, buf);
        } else {
            self.fast_zeroize();
            self.clear();
        }

        result
    }
}

impl EncodeSlice for String {
    fn encode_slice_into(slice: &mut [Self], buf: &mut CodecBuffer) -> Result<(), EncodeError> {
        for elem in slice.iter_mut() {
            elem.encode_into(buf)?;
        }

        Ok(())
    }
}

impl TryDecode for String {
    #[inline(always)]
    fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let mut size = Zeroizing::from(&mut 0usize);

        process_header(buf, &mut size)?;

        self.prealloc(*size);

        // SAFETY: prealloc sets len, we decode into those bytes
        let bytes = unsafe { self.as_bytes_mut() };
        // Note: This error branch is unreachable since process_header already validates
        // buffer length. We use `?` instead of expect/unwrap to keep the code panic-free.
        u8::decode_slice_from(bytes, buf)?;

        // Validate UTF-8
        if core::str::from_utf8(self.as_bytes()).is_err() {
            return Err(DecodeError::PreconditionViolated);
        }

        Ok(())
    }
}

impl Decode for String {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let result = self.try_decode_from(buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            cleanup_decode_error(self, buf);
        }

        result
    }
}

impl DecodeSlice for String {
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for elem in slice.iter_mut() {
            elem.decode_from(buf)?;
        }

        Ok(())
    }
}

impl PreAlloc for String {
    const ZERO_INIT: bool = true;

    fn prealloc(&mut self, size: usize) {
        self.clear();
        self.shrink_to_fit();
        self.reserve_exact(size);

        // SAFETY: We're setting len after reserving capacity
        // The bytes will be written by decode before being read as UTF-8
        unsafe {
            let vec = self.as_mut_vec();
            memutil::fast_zeroize_vec(vec);
            vec.set_len(size);
        }
    }
}
