// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Proxy codec implementation for `RedoubtVec<T>`.
//!
//! All codec traits simply delegate to the inner `Vec<T>` implementation.

use redoubt_alloc::RedoubtVec;
use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice, PreAlloc};

impl<T> BytesRequired for RedoubtVec<T>
where
    T: BytesRequired + FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        // Delegate to inner Vec
        self.as_vec().encode_bytes_required()
    }
}

impl<T> Encode for RedoubtVec<T>
where
    T: EncodeSlice + BytesRequired + FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        // Delegate to inner Vec
        self.as_mut_vec().encode_into(buf)
    }
}

impl<T> Decode for RedoubtVec<T>
where
    T: DecodeSlice + PreAlloc + FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        // Delegate to inner Vec
        self.as_mut_vec().decode_from(buf)
    }
}
