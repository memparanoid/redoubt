// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Proxy codec implementation for `RedoubtArray<T, N>`.
//!
//! All codec traits simply delegate to the inner `[T; N]` implementation.

use redoubt_alloc::RedoubtArray;
use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice};

impl<T, const N: usize> BytesRequired for RedoubtArray<T, N>
where
    T: BytesRequired + FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        // Delegate to inner [T; N]
        self.as_array().encode_bytes_required()
    }
}

impl<T, const N: usize> Encode for RedoubtArray<T, N>
where
    T: EncodeSlice + BytesRequired + FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        // Delegate to inner [T; N]
        self.as_mut_array().encode_into(buf)
    }
}

impl<T, const N: usize> Decode for RedoubtArray<T, N>
where
    T: DecodeSlice + FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        // Delegate to inner [T; N]
        self.as_mut_array().decode_from(buf)
    }
}
