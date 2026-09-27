// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Proxy codec implementation for `RedoubtSecret<T>`.
//!
//! All codec traits delegate to the value it holds: the wire is `T`'s, with no
//! header of the secret's own.

use redoubt_secret::RedoubtSecret;
use redoubt_zero::{FastZeroizable, ZeroizationProbe};

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, Encode};

impl<T> BytesRequired for RedoubtSecret<T>
where
    T: BytesRequired + FastZeroizable + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        self.as_ref().encode_bytes_required()
    }
}

impl<T> Encode for RedoubtSecret<T>
where
    T: Encode + BytesRequired + FastZeroizable + ZeroizationProbe,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        self.as_mut().encode_into(buf)
    }
}

impl<T> Decode for RedoubtSecret<T>
where
    T: Decode + FastZeroizable + ZeroizationProbe,
{
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        self.as_mut().decode_from(buf)
    }
}
