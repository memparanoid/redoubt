// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::error::OverflowError;
use crate::tests::primitives::utils::{equidistant_unsigned, EQUIDISTANT_SAMPLE_SIZE};
use crate::traits::TryEncode;
use crate::EncodeError;

use super::utils::test_collection_varying_capacities;

fn test_string_varying_capacities(set: &[u8]) {
    test_collection_varying_capacities(
        set,
        |cap| String::with_capacity(cap),
        |s, slice| {
            s.clear();
            // Convert bytes to valid ASCII chars (mod 128)
            for &b in slice {
                s.push((b % 128) as char);
            }
        },
        |a, b| a == b,
    );
}

#[test]
fn test_string_varying_capacities_u8() {
    let set = equidistant_unsigned::<u8>(EQUIDISTANT_SAMPLE_SIZE);
    test_string_varying_capacities(&set);
}

// string_bytes_required

#[test]
fn test_string_bytes_required_ok() {
    use crate::collections::string::string_bytes_required;

    let result = string_bytes_required(100);

    assert!(result.is_ok());
}

#[test]
fn test_string_bytes_required_overflow() {
    use crate::collections::string::string_bytes_required;

    let result = string_bytes_required(usize::MAX);

    assert!(result.is_err());
    match result {
        Err(OverflowError { reason }) => {
            assert_eq!(reason, "String bytes_required overflow");
        }
        _ => panic!("Expected OverflowError"),
    }
}

// TryEncode

#[test]
fn test_string_try_encode_propagates_write_header_error() {
    use crate::error::CodecBufferError;

    let mut s = String::from("hello");
    let mut buf = Buffer::new(1); // Too small for header

    let result = s.try_encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::CodecBufferError(CodecBufferError::CapacityExceeded))
    ));
}

#[test]
fn test_string_try_encode_propagates_encode_slice_error() {
    use crate::collections::helpers::header_size;
    use crate::error::CodecBufferError;

    let mut s = String::from("hello");
    let mut buf = Buffer::new(header_size()); // Fits header, not data

    let result = s.try_encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::CodecBufferError(CodecBufferError::CapacityExceeded))
    ));
}
