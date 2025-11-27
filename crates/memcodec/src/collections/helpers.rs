// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroizing;

use membuffer::Buffer;

use crate::error::{CodecBufferError, DecodeError};
use crate::traits::{CodecBuffer, DecodeBuffer};

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

pub fn process_header(
    mut buf: &mut &mut [u8],
    output_size: &mut usize,
    output_bytes_required: &mut usize,
) -> Result<(), DecodeError> {
    let header_size = Zeroizing::new(header_size());

    if buf.len() < *header_size {
        return Err(DecodeError::PreconditionViolated);
    }

    buf.read_usize(output_size)?;
    buf.read_usize(output_bytes_required)?;

    if buf.len() < *output_bytes_required {
        return Err(DecodeError::PreconditionViolated);
    }

    Ok(())
}
