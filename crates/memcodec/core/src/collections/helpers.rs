// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::error::{CodecBufferError, DecodeError};
use crate::traits::{CodecBuffer, DecodeBuffer};
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
