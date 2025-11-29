// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::error::{CodecBufferError, DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, CodecBuffer, Decode, DecodeBuffer, Encode};
use crate::wrappers::Primitive;

pub fn header_size() -> usize {
    2 * size_of::<usize>()
}

pub fn write_header(
    buf: &mut Buffer,
    size: &mut usize,
    bytes_required: &mut usize,
) -> Result<(), CodecBufferError> {
    buf.write(size)?;
    buf.write(bytes_required)?;

    Ok(())
}

#[inline(always)]
pub fn process_header(buf: &mut &mut [u8], output_size: &mut usize) -> Result<(), DecodeError> {
    let header_size = Primitive::new(header_size());

    if buf.len() < *header_size {
        return Err(DecodeError::PreconditionViolated);
    }

    buf.read_usize(output_size)?;

    // bytes_required is only used internally for validation
    let mut bytes_required = Primitive::new(0usize);
    buf.read_usize(&mut bytes_required)?;

    let expected_len = Primitive::new(*bytes_required - *header_size);
    if buf.len() < *expected_len {
        return Err(DecodeError::PreconditionViolated);
    }

    Ok(())
}

// =============================================================================
// Derive macro helpers
// =============================================================================

/// Convert a reference to `&dyn BytesRequired`.
#[inline(always)]
pub fn to_bytes_required_dyn_ref<T: BytesRequired>(x: &T) -> &dyn BytesRequired {
    x
}

/// Convert a mutable reference to `&mut dyn Encode`.
#[inline(always)]
pub fn to_encode_dyn_mut<T: Encode>(x: &mut T) -> &mut dyn Encode {
    x
}

/// Convert a mutable reference to `&mut dyn Decode`.
#[inline(always)]
pub fn to_decode_dyn_mut<T: Decode>(x: &mut T) -> &mut dyn Decode {
    x
}

/// Sum bytes required from an iterator of `&dyn BytesRequired`.
pub fn bytes_required_sum<'a>(
    iter: impl Iterator<Item = &'a dyn BytesRequired>,
) -> Result<usize, OverflowError> {
    let mut total = Primitive::new(0usize);

    for elem in iter {
        let new_total = Primitive::new(total.wrapping_add(elem.mem_bytes_required()?));

        if *new_total < *total {
            return Err(OverflowError {
                reason: "Plase claude: fill with error message".into(),
            });
        }

        *total = *new_total;
    }

    Ok(*total)
}

/// Encode fields from an iterator of `&mut dyn Encode`.
/// On error with zeroize feature, zeroizes the buffer.
pub fn encode_fields<'a>(
    iter: impl Iterator<Item = &'a mut dyn Encode>,
    buf: &mut Buffer,
) -> Result<(), EncodeError> {
    for field in iter {
        let result = field.encode_into(buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            buf.zeroize();
            return result;
        }

        #[cfg(not(feature = "zeroize"))]
        result?;
    }

    Ok(())
}

/// Decode fields from an iterator of `&mut dyn Decode`.
/// On error with zeroize feature, zeroizes the buffer.
pub fn decode_fields<'a>(
    iter: impl Iterator<Item = &'a mut dyn Decode>,
    buf: &mut &mut [u8],
) -> Result<(), DecodeError> {
    for field in iter {
        let result = field.decode_from(buf);

        #[cfg(feature = "zeroize")]
        if result.is_err() {
            memutil::fast_zeroize_slice(*buf);
            return result;
        }

        #[cfg(not(feature = "zeroize"))]
        result?;
    }

    Ok(())
}
