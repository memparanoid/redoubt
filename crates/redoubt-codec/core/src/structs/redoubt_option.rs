// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Proxy codec implementation for `RedoubtOption<T>`.
//!
//! All codec traits simply delegate to the inner `Option<T>` implementation.

use redoubt_alloc::RedoubtOption;
use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, Encode};

impl<T> BytesRequired for RedoubtOption<T>
where
    T: BytesRequired + FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        // Delegate to inner Option
        self.as_option().encode_bytes_required()
    }
}

impl<T> Encode for RedoubtOption<T>
where
    T: Encode + BytesRequired + FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        // Delegate to inner Option
        self.as_mut_option().encode_into(buf)
    }
}

impl<T> Decode for RedoubtOption<T>
where
    T: Decode + Default + FastZeroizable + ZeroizeMetadata + ZeroizationProbe,
{
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        // Delegate to inner Option
        self.as_mut_option().decode_from(buf)
    }
}
