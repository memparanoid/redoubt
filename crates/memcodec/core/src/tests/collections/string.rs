// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::error::OverflowError;
use crate::tests::primitives::utils::{equidistant_unsigned, EQUIDISTANT_SAMPLE_SIZE};
use crate::traits::TryEncode;
use crate::EncodeError;

use super::utils::test_collection_varying_capacities;

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

// Encode

#[test]
fn test_string_encode_into_propagates_try_encode_into_error() {
    use crate::error::CodecBufferError;
    use crate::traits::Encode;
    use memzer::ZeroizationProbe;

    // Force try_encode_into to fail via buffer too small, then check zeroization
    let mut s = String::from("hello");
    let mut buf = Buffer::new(1); // Too small

    let result = s.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::CodecBufferError(CodecBufferError::CapacityExceeded))
    ));
    // Check zeroization
    assert!(s.is_empty());
    assert!(buf.is_zeroized());
}

// EncodeSlice

#[test]
fn test_string_encode_slice_ok() {
    use crate::collections::helpers::header_size;
    use crate::traits::EncodeSlice;

    let mut slice = [String::from("hello"), String::from("world")];
    let buf_size = 2 * header_size() + 5 + 5; // 2 headers + "hello" + "world"
    let mut buf = Buffer::new(buf_size);

    let result = String::encode_slice_into(&mut slice, &mut buf);

    assert!(result.is_ok());
}

#[test]
fn test_string_encode_slice_propagates_encode_into_error() {
    use crate::error::CodecBufferError;
    use crate::traits::EncodeSlice;

    let mut slice = [String::from("hello"), String::from("world")];
    let mut buf = Buffer::new(1); // Too small

    let result = String::encode_slice_into(&mut slice, &mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::CodecBufferError(CodecBufferError::CapacityExceeded))
    ));
}

// TryDecode

#[test]
fn test_string_try_decode_propagates_process_header_error() {
    use crate::traits::TryDecode;
    use crate::DecodeError;

    let mut s = String::new();
    let mut buf = [0u8; 1]; // Too small for header

    let result = s.try_decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_string_try_decode_utf8_validation_error() {
    use crate::collections::helpers::header_size;
    use crate::traits::{Encode, TryDecode};
    use crate::DecodeError;

    // Encode valid string
    let mut s = String::from("hello");
    let mut buf = Buffer::new(header_size() + s.len());
    s.encode_into(&mut buf).expect("encode failed");

    // Corrupt buffer with invalid UTF-8 (0xFF is never valid)
    let data_start = header_size();
    buf.as_mut_slice()[data_start] = 0xFF;

    // Decode should fail UTF-8 validation
    let mut decoded = String::new();
    let result = decoded.try_decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

// Decode

#[test]
fn test_string_decode_from_propagates_try_decode_from_error() {
    use crate::traits::Decode;
    use crate::DecodeError;

    // Start with a string with data to verify zeroization
    let mut s = String::from("existing data");
    let mut buf = [0u8; 1]; // Too small for header
    let mut slice = buf.as_mut_slice();

    let result = s.decode_from(&mut slice);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
    // Check zeroization - string should be cleared
    assert!(s.is_empty());
    assert!(slice.iter().all(|&b| b == 0));
}

// DecodeSlice

#[test]
fn test_string_decode_slice_ok() {
    use crate::collections::helpers::header_size;
    use crate::traits::{DecodeSlice, EncodeSlice};

    // Encode first
    let mut slice = [String::from("hello"), String::from("world")];
    let buf_size = 2 * header_size() + 5 + 5;
    let mut buf = Buffer::new(buf_size);
    String::encode_slice_into(&mut slice, &mut buf).expect("encode failed");

    // Decode
    let mut decoded = [String::new(), String::new()];
    let result = String::decode_slice_from(&mut decoded, &mut buf.as_mut_slice());

    assert!(result.is_ok());
    assert_eq!(decoded[0], "hello");
    assert_eq!(decoded[1], "world");
}

#[test]
fn test_string_decode_slice_propagates_decode_from_error() {
    use crate::traits::DecodeSlice;
    use crate::DecodeError;

    let mut slice = [String::from("existing"), String::from("data")];
    let mut buf = [0u8; 1]; // Too small

    let result = String::decode_slice_from(&mut slice, &mut buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

// Integration test

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
