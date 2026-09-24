// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::{FastZeroizable, ZeroizeMetadata};

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, Encode, TryDecode, TryEncode};
use redoubt_zero::ZeroizingGuard;

use super::helpers::{header_size, process_header, write_header};

/// Cleanup function for encode errors. Marked #[cold] to keep it out of the hot path.
#[cold]
#[inline(never)]
pub(crate) fn cleanup_encode_error<T: FastZeroizable + ZeroizeMetadata>(
    opt: &mut Option<T>,
    buf: &mut RedoubtCodecBuffer,
) {
    opt.fast_zeroize();
    buf.fast_zeroize();
}

/// Cleanup function for decode errors. Marked #[cold] to keep it out of the hot path.
#[cold]
#[inline(never)]
pub(crate) fn cleanup_decode_error<T: FastZeroizable + ZeroizeMetadata>(
    opt: &mut Option<T>,
    buf: &mut &mut [u8],
) {
    opt.fast_zeroize();
    buf.fast_zeroize();
}

impl<T> BytesRequired for Option<T>
where
    T: BytesRequired,
{
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        let header = header_size();

        match self {
            None => Ok(header),
            Some(inner) => {
                let inner_bytes = inner.encode_bytes_required()?;
                let total = header.wrapping_add(inner_bytes);

                if total < header {
                    return Err(OverflowError {
                        reason: "Option::encode_bytes_required overflow".into(),
                    });
                }

                Ok(total)
            }
        }
    }
}

impl<T> TryEncode for Option<T>
where
    T: Encode + BytesRequired + FastZeroizable + ZeroizeMetadata,
{
    fn try_encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        let mut bytes_required = ZeroizingGuard::from_mut(&mut self.encode_bytes_required()?);

        match self {
            None => {
                // size = 0 indicates None
                let mut size = ZeroizingGuard::from_mut(&mut 0usize);
                write_header(buf, &mut size, &mut bytes_required)?;
            }
            Some(inner) => {
                // size = 1 indicates Some
                let mut size = ZeroizingGuard::from_mut(&mut 1usize);
                write_header(buf, &mut size, &mut bytes_required)?;

                inner.encode_into(buf)?;
            }
        }

        Ok(())
    }
}

impl<T> Encode for Option<T>
where
    T: Encode + BytesRequired + FastZeroizable + ZeroizeMetadata,
{
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        let result = self.try_encode_into(buf);

        if result.is_err() {
            cleanup_encode_error(self, buf);
        } else {
            self.fast_zeroize();
        }

        result
    }
}

impl<T> TryDecode for Option<T>
where
    T: Decode + Default + FastZeroizable + ZeroizeMetadata,
{
    #[inline(always)]
    fn try_decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let mut size = ZeroizingGuard::from_mut(&mut 0);

        process_header(buf, &mut size)?;

        match *size {
            0 => {
                // None
                self.fast_zeroize();

                *self = None;
            }
            1 => {
                // Some, decoded in place and handed over by swap: a move of an
                // inline value leaves a copy where it was.
                let mut slot = Some(T::default());

                slot.as_mut()
                    .expect("Infallible: slot was just made Some")
                    .decode_from(buf)?;

                self.fast_zeroize();

                redoubt_mem::swap(self, &mut slot);
            }
            _ => {
                return Err(DecodeError::PreconditionViolated);
            }
        }

        Ok(())
    }
}

impl<T> Decode for Option<T>
where
    T: Decode + Default + FastZeroizable + ZeroizeMetadata,
{
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let result = self.try_decode_from(buf);

        if result.is_err() {
            cleanup_decode_error(self, buf);
        }

        result
    }
}
