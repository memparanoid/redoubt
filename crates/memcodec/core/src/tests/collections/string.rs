// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::codec_buffer::CodecBuffer;
#[cfg(feature = "zeroize")]
use memzer::ZeroizationProbe;

use crate::collections::helpers::header_size;
use crate::collections::string::string_bytes_required;
use crate::error::{CodecBufferError, OverflowError};
use crate::tests::primitives::utils::{EQUIDISTANT_SAMPLE_SIZE, equidistant_unsigned};
use crate::traits::{Decode, DecodeSlice, Encode, EncodeSlice, TryDecode, TryEncode};
use crate::{BytesRequired, DecodeError, EncodeError};

use super::utils::test_collection_varying_capacities;

// Bytes Required

#[test]
fn test_string_bytes_required_ok() {
    let result = string_bytes_required(100);

    assert!(result.is_ok());
}

#[test]
fn test_string_bytes_required_overflow() {
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
    let mut s = String::from("hello");
    let mut buf = CodecBuffer::new(1); // Too small for header

    let result = s.try_encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::CodecBufferError(
            CodecBufferError::CapacityExceeded
        ))
    ));
}

#[test]
fn test_string_try_encode_propagates_encode_slice_error() {
    let mut s = String::from("hello");
    let mut buf = CodecBuffer::new(header_size()); // Fits header, not data

    let result = s.try_encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::CodecBufferError(
            CodecBufferError::CapacityExceeded
        ))
    ));
}

// EncodeSlice

#[test]
fn test_string_encode_slice_ok() {
    let mut s_slice = [String::from("hello"), String::from("world")];
    let buf_size = s_slice
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(buf_size);

    let result = String::encode_slice_into(&mut s_slice, &mut buf);

    assert!(result.is_ok());

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(s_slice.iter().all(|s| s.is_zeroized()));
    }
}

#[test]
fn test_string_encode_slice_propagates_encode_into_error() {
    let mut s_slice = [String::from("hello"), String::from("world")];
    let mut buf = CodecBuffer::new(1); // Too small

    let result = String::encode_slice_into(&mut s_slice, &mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::CodecBufferError(
            CodecBufferError::CapacityExceeded
        ))
    ));
}

// Encode

#[test]
fn test_string_encode_into_propagates_try_encode_into_error() {
    // Force try_encode_into to fail via buffer too small, then check zeroization
    let mut s = String::from("hello");
    let mut buf = CodecBuffer::new(1); // Too small

    let result = s.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::CodecBufferError(
            CodecBufferError::CapacityExceeded
        ))
    ));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(s.is_zeroized());
    }
}

#[test]
fn test_string_encode_ok() {
    let mut s = String::from("hello world");
    let bytes_required = s
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);

    let result = s.encode_into(&mut buf);

    assert!(result.is_ok());

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(s.is_zeroized());
    }
}

// TryDecode

#[test]
fn test_string_try_decode_propagates_process_header_error() {
    let mut s = String::new();
    let mut buf = [0u8; 1]; // Too small for header

    let result = s.try_decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_string_try_decode_utf8_validation_error() {
    let mut s = String::from("hello");
    let bytes_required = s
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);

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

// DecodeSlice

#[test]
fn test_string_slice_roundtrip_ok() {
    // Encode
    let mut s_slice = [String::from("hello"), String::from("world")];
    let bytes_required = s_slice
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);

    String::encode_slice_into(&mut s_slice, &mut buf).expect("encode failed");

    // Decode
    let mut decoded = [String::new(), String::new()];
    let mut decode_buf = buf.as_mut_slice();
    let result = String::decode_slice_from(&mut decoded, &mut decode_buf);

    assert!(result.is_ok());
    assert_eq!(decoded[0], "hello");
    assert_eq!(decoded[1], "world");

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(s_slice.is_zeroized());
        assert!(decode_buf.iter().all(|&b| b == 0));
    }
}

#[test]
fn test_string_decode_slice_propagates_decode_from_error() {
    let mut s_slice = [String::from("existing"), String::from("data")];
    let mut buf = [0u8; 1]; // Too small
    let mut decode_buf = buf.as_mut_slice();

    let result = String::decode_slice_from(&mut s_slice, &mut decode_buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

// Decode

#[test]
fn test_string_decode_from_propagates_try_decode_from_error() {
    // Start with a string with data to verify zeroization
    let mut s = String::from("existing data");

    let mut buf = [0u8; 1]; // Too small for header
    let mut decode_buf = buf.as_mut_slice();
    let result = s.decode_from(&mut decode_buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(s.is_zeroized());
        assert!(decode_buf.iter().all(|&b| b == 0));
    }
}

// Roundtrip (this includes test_string_decode_from_ok)

#[test]
fn test_string_roundtrip_ok() {
    // Encode
    let mut s = String::from("hello world");
    let bytes_required = s
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);

    s.encode_into(&mut buf).expect("encode failed");

    // Decode
    {
        let mut decoded = String::new();

        let mut decode_buf = buf.as_mut_slice();
        let result = decoded.decode_from(&mut decode_buf);

        assert!(result.is_ok());
        assert_eq!(decoded, "hello world");

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(decode_buf.iter().all(|&b| b == 0));
        }
    }

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.as_slice().iter().all(|&b| b == 0));
        assert!(s.is_zeroized());
    }
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
