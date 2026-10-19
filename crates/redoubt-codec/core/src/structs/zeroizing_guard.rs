// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizingGuard};

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, Encode};

impl<T> BytesRequired for ZeroizingGuard<T>
where
    T: BytesRequired + FastZeroizable + ZeroizationProbe + Default,
{
    #[inline(always)]
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        let inner: &T = self;

        inner.encode_bytes_required()
    }
}

impl<T> Encode for ZeroizingGuard<T>
where
    T: Encode + FastZeroizable + ZeroizationProbe + Default,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        let inner: &mut T = self;

        inner.encode_into(buf)
    }
}

impl<T> Decode for ZeroizingGuard<T>
where
    T: Decode + FastZeroizable + ZeroizationProbe + Default,
{
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let inner: &mut T = self;

        inner.decode_from(buf)
    }
}
