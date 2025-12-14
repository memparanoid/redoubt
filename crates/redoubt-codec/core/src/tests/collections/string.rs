// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::codec_buffer::RedoubtCodecBuffer;
#[cfg(feature = "zeroize")]
use redoubt_zero::ZeroizationProbe;

use crate::collections::helpers::header_size;
use crate::collections::string::string_bytes_required;
use crate::error::{OverflowError, RedoubtCodecBufferError};
use crate::tests::primitives::utils::{EQUIDISTANT_SAMPLE_SIZE, equidistant_unsigned};
use crate::traits::{Decode, DecodeSlice, Encode, EncodeSlice};
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
fn test_string_encode_propagates_write_header_error() {
    let mut s = String::from("hello");
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small for header

    let result = s.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::RedoubtCodecBufferError(
            RedoubtCodecBufferError::CapacityExceeded
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
fn test_string_encode_into_propagates_encode_slice_error() {
    let mut s = String::from("hello");
    let mut buf = RedoubtCodecBuffer::with_capacity(header_size()); // Fits header, not data

    let result = s.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::RedoubtCodecBufferError(
            RedoubtCodecBufferError::CapacityExceeded
        ))
    ));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(s.is_zeroized());
    }
}

// Encode

#[test]
fn test_string_encode_into_propagates_try_encode_into_error() {
    // Force try_encode_into to fail via buffer too small, then check zeroization
    let mut s = String::from("hello");
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small

    let result = s.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::RedoubtCodecBufferError(
            RedoubtCodecBufferError::CapacityExceeded
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
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    let result = s.encode_into(&mut buf);

    assert!(result.is_ok());

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(s.is_zeroized());
    }
}

// EncodeSlice

#[test]
fn test_string_encode_slice_ok() {
    let mut s_slice = [String::from("hello"), String::from("world")];
    let buf_size = s_slice
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(buf_size);

    let result = String::encode_slice_into(&mut s_slice, &mut buf);

    assert!(result.is_ok());

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(s_slice.is_zeroized());
    }
}

#[test]
fn test_string_encode_slice_propagates_encode_into_error() {
    let mut s_slice = [String::from("hello"), String::from("world")];
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small

    let result = String::encode_slice_into(&mut s_slice, &mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::RedoubtCodecBufferError(
            RedoubtCodecBufferError::CapacityExceeded
        ))
    ));
}

// TryDecode

#[test]
fn test_string_decode_from_propagates_process_header_error() {
    let mut s = String::new();
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small for header;

    let mut decode_buf = buf.export_as_vec();
    let result = s.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(s.is_zeroized());
    }
}

#[test]
fn test_string_decode_from_utf8_validation_error() {
    let mut s = String::from("hello");
    let bytes_required = s
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    s.encode_into(&mut buf).expect("encode failed");

    // Corrupt buffer with invalid UTF-8 (0xFF is never valid)
    let data_start = header_size();
    buf.as_mut_slice()[data_start] = 0xFF;

    // Decode should fail UTF-8 validation
    let mut decoded = String::new();
    let mut decode_buf = buf.export_as_vec();
    let result = decoded.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    {
        // Buffer is not zeroized if not exported as vec.
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        println!("DECODED: {:?}", decoded);
        // assert!(decoded.is_zeroized());
    }
}

// Decode

#[test]
fn test_string_decode_from_propagates_error() {
    // Start with a string with data to verify zeroization
    let mut s = String::from("existing data");

    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small
    let mut decode_buf = buf.export_as_vec();
    let result = s.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(s.is_zeroized());
    }
}

// DecodeSlice

#[test]
fn test_string_slice_roundtrip_ok() {
    // Encode
    let mut s_slice = [String::from("hello"), String::from("world")];
    let bytes_required = s_slice
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    String::encode_slice_into(&mut s_slice, &mut buf).expect("encode failed");

    // Decode
    let mut decoded = [String::new(), String::new()];
    let mut decode_buf = buf.export_as_vec();
    let result = String::decode_slice_from(&mut decoded, &mut decode_buf.as_mut_slice());

    assert!(result.is_ok());
    assert_eq!(decoded[0], "hello");
    assert_eq!(decoded[1], "world");

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(s_slice.is_zeroized());
    }
}

#[test]
fn test_string_decode_slice_propagates_decode_from_error() {
    let mut s_slice = [String::from("existing"), String::from("data")];
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small
    let mut decode_buf = buf.export_as_vec();

    let result = String::decode_slice_from(&mut s_slice, &mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

// Roundtrip (this includes test_string_decode_from_ok)

#[test]
fn test_string_roundtrip_ok() {
    // Encode
    let mut s = String::from("hello world");
    let bytes_required = s
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    s.encode_into(&mut buf).expect("encode failed");

    // Decode
    {
        let mut decoded = String::new();

        let mut decode_buf = buf.export_as_vec();
        let result = decoded.decode_from(&mut decode_buf.as_mut_slice());

        assert!(result.is_ok());
        assert_eq!(decoded, "hello world");

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(decode_buf.is_zeroized());
        }
    }

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(s.is_zeroized());
    }
}

// Integration test

fn test_string_varying_capacities(set: &[u8]) {
    test_collection_varying_capacities(
        set,
        String::with_capacity,
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
