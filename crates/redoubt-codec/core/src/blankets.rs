// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Blanket implementations for common wrapper types.

use alloc::boxed::Box;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, Encode};

// ═══════════════════════════════════════════════════════════════════════════════
// Box<T>
// ═══════════════════════════════════════════════════════════════════════════════

impl<T> BytesRequired for Box<T>
where
    T: BytesRequired,
{
    #[inline(always)]
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        (**self).encode_bytes_required()
    }
}

impl<T> Encode for Box<T>
where
    T: Encode,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        (**self).encode_into(buf)
    }
}

impl<T> Decode for Box<T>
where
    T: Decode,
{
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        (**self).decode_from(buf)
    }
}
