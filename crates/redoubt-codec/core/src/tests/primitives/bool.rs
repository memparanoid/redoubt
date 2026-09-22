// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeBufferError, DecodeError};
use crate::traits::{Decode, DecodeSlice, EncodeSlice, PreAlloc};

use super::utils::test_all_pairs;

#[test]
fn test_bool_all_pairs() {
    let set = [true, false];
    test_all_pairs(&set);
}

// encode_slice_into

/// The byte each value becomes is the wire, so it is asserted rather than
/// round-tripped: a pair of conversions that disagreed the same way in both
/// directions would round-trip and still be wrong.
#[test]
fn test_bool_encode_slice_into_writes_one_byte_each() -> Result<(), Box<dyn std::error::Error>> {
    let mut values = [true, false, true];
    let mut buf = RedoubtCodecBuffer::with_capacity(values.len());

    bool::encode_slice_into(&mut values, &mut buf)?;

    assert_eq!(buf.as_slice(), &[1, 0, 1]);

    Ok(())
}

// decode_from

#[test]
fn test_bool_decode_from_empty_buffer() {
    let mut value = false;
    let mut empty_buf = &mut [][..];
    let result = value.decode_from(&mut empty_buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(DecodeError::DecodeBufferError(
            DecodeBufferError::OutOfBounds
        ))
    ));
}

/// Swept rather than sampled: what is being pinned is that the match has no
/// hole, and a byte that slips through reaches a `bool` as a bit pattern it
/// never had.
#[test]
fn test_bool_decode_from_reports_every_byte_that_is_not_zero_or_one() {
    for byte in 2..=u8::MAX {
        let mut value = false;
        let mut bytes = [byte];

        let result = value.decode_from(&mut &mut bytes[..]);

        assert!(
            matches!(result, Err(DecodeError::PreconditionViolated)),
            "{byte} was taken for a bool"
        );
    }
}

// decode_slice_from

#[test]
fn test_bool_decode_slice_from_reports_a_byte_that_is_not_zero_or_one() {
    let mut values = [false; 2];
    let mut bytes = [0_u8, 2];

    let result = bool::decode_slice_from(&mut values, &mut &mut bytes[..]);

    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_bool_decode_slice_from_reads_one_byte_each() -> Result<(), Box<dyn std::error::Error>> {
    let mut values = [false; 3];
    let mut bytes = [1_u8, 0, 1];

    bool::decode_slice_from(&mut values, &mut &mut bytes[..])?;

    assert_eq!(values, [true, false, true]);

    Ok(())
}

// prealloc

#[test]
fn test_bool_prealloc_noop() {
    let mut value = true;

    value.prealloc(999);

    assert!(value);
}
