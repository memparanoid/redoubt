// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

#[cfg(feature = "zeroize")]
use smallvec::SmallVec;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::error::{CodecBufferError, DecodeError, EncodeError, OverflowError};
use crate::traits::{
    BytesRequired, CodecBuffer, Decode, DecodeBuffer, DecodeZeroize, Encode, EncodeZeroize,
};
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

    // Infallible: precondition ensures buf.len() >= header_size (2 * usize)
    // Error branch kept for panic-free guarantees, cannot be tested
    buf.read_usize(output_size)?;

    // bytes_required is only used internally for validation
    let mut bytes_required = Primitive::new(0usize);

    // Infallible: precondition ensures buf.len() >= header_size (2 * usize)
    // Error branch kept for panic-free guarantees, cannot be tested
    buf.read_usize(&mut bytes_required)?;

    if *header_size > *bytes_required {
        return Err(DecodeError::PreconditionViolated);
    }

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

/// Convert a mutable reference to `&mut dyn EncodeZeroize`.
#[inline(always)]
pub fn to_encode_zeroize_dyn_mut<T: EncodeZeroize>(x: &mut T) -> &mut dyn EncodeZeroize {
    x
}

/// Convert a mutable reference to `&mut dyn DecodeZeroize`.
#[inline(always)]
pub fn to_decode_zeroize_dyn_mut<T: DecodeZeroize>(x: &mut T) -> &mut dyn DecodeZeroize {
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
                reason: "bytes_required_sum overflow".into(),
            });
        }

        *total = *new_total;
    }

    Ok(*total)
}

/// Encode fields from an iterator of `&mut dyn EncodeZeroize`.
/// On error with zeroize feature, zeroizes all fields and the buffer.
pub fn encode_fields<'a>(
    iter: impl Iterator<Item = &'a mut dyn EncodeZeroize>,
    buf: &mut Buffer,
) -> Result<(), EncodeError> {
    let mut result = Ok(());

    for field in iter {
        #[cfg(feature = "zeroize")]
        if result.is_err() {
            field.fast_zeroize();
            continue;
        }

        if let Err(e) = field.encode_into(buf) {
            result = Err(e);

            #[cfg(feature = "zeroize")]
            {
                field.fast_zeroize();
                buf.zeroize();
            }

            #[cfg(not(feature = "zeroize"))]
            break;
        }
    }

    result
}

/// Decode fields from an iterator of `&mut dyn DecodeZeroize`.
/// On error with zeroize feature, zeroizes all fields and the buffer.
pub fn decode_fields<'a>(
    iter: impl Iterator<Item = &'a mut dyn DecodeZeroize>,
    buf: &mut &mut [u8],
) -> Result<(), DecodeError> {
    #[cfg(feature = "zeroize")]
    let mut decoded: SmallVec<[&'a mut dyn DecodeZeroize; 32]> = SmallVec::new();
    let mut result = Ok(());

    for field in iter {
        #[cfg(feature = "zeroize")]
        if result.is_err() {
            field.fast_zeroize();
            continue;
        }

        if let Err(e) = field.decode_from(buf) {
            result = Err(e);

            #[cfg(feature = "zeroize")]
            {
                field.fast_zeroize();

                // Zeroize all previously decoded fields
                for decoded_field in decoded.iter_mut() {
                    decoded_field.fast_zeroize();
                }

                memutil::fast_zeroize_slice(*buf);
            }

            #[cfg(not(feature = "zeroize"))]
            break;
        } else {
            #[cfg(feature = "zeroize")]
            decoded.push(field);
        }
    }

    result
}
