// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Proxy codec implementation for `RedoubtString`.
//!
//! All codec traits simply delegate to the inner `String` implementation.

use redoubt_alloc::RedoubtString;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, Encode};

impl BytesRequired for RedoubtString {
    #[inline(always)]
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        // Delegate to inner String
        self.as_string().encode_bytes_required()
    }
}

impl Encode for RedoubtString {
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        // Delegate to inner String
        self.as_mut_string().encode_into(buf)
    }
}

impl Decode for RedoubtString {
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        // Delegate to inner String
        self.as_mut_string().decode_from(buf)
    }
}
