// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;
#[cfg(feature = "zeroize")]
use memzer::ZeroizationProbe;

use crate::collections::helpers::{
    bytes_required_sum, decode_fields, encode_fields, to_bytes_required_dyn_ref, to_decode_dyn_mut,
    to_decode_zeroize_dyn_mut, to_encode_dyn_mut, to_encode_zeroize_dyn_mut,
};
use crate::error::OverflowError;
use crate::support::test_utils::{TestBreaker, TestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, DecodeZeroize, Encode, EncodeZeroize};

// to_bytes_required_dyn_ref

#[test]
fn test_to_bytes_required_dyn_ref() {
    let tb = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let dyn_ref: &dyn BytesRequired = to_bytes_required_dyn_ref(&tb);

    assert_eq!(
        dyn_ref.mem_bytes_required().expect("Failed"),
        tb.mem_bytes_required().expect("Failed")
    );
}

// to_encode_dyn_mut

#[test]
fn test_to_encode_dyn_mut() {
    let mut tb = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let mut buf = Buffer::new(1024);

    let dyn_mut: &mut dyn Encode = to_encode_dyn_mut(&mut tb);
    let result = dyn_mut.encode_into(&mut buf);

    assert!(result.is_ok());
}

// to_decode_dyn_mut

#[test]
fn test_to_decode_dyn_mut() {
    // First encode
    let mut tb = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let bytes_required = tb.mem_bytes_required().expect("Failed");
    let mut buf = Buffer::new(bytes_required);
    tb.encode_into(&mut buf).expect("Failed to encode");

    // Decode
    let mut decoded = TestBreaker::default();
    let dyn_mut: &mut dyn Decode = to_decode_dyn_mut(&mut decoded);
    let result = dyn_mut.decode_from(&mut buf.as_mut_slice());

    assert!(result.is_ok());
    assert_eq!(decoded.data, 100);
}

// bytes_required_sum

#[test]
fn test_bytes_required_sum_ok() {
    let tb1 = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let tb2 = TestBreaker::new(TestBreakerBehaviour::None, 200);

    let refs: [&dyn BytesRequired; 2] = [
        to_bytes_required_dyn_ref(&tb1),
        to_bytes_required_dyn_ref(&tb2),
    ];

    let result = bytes_required_sum(refs.into_iter());

    assert!(result.is_ok());
}

#[test]
fn test_bytes_required_sum_element_error() {
    let tb1 = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let tb2 = TestBreaker::new(TestBreakerBehaviour::ForceBytesRequiredOverflow, 200);

    let refs: [&dyn BytesRequired; 2] = [
        to_bytes_required_dyn_ref(&tb1),
        to_bytes_required_dyn_ref(&tb2),
    ];

    let result = bytes_required_sum(refs.into_iter());

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(OverflowError { reason }) if reason == "TestBreaker forced overflow"
    ));
}

#[test]
fn test_bytes_required_sum_overflow() {
    let tb1 = TestBreaker::new(TestBreakerBehaviour::BytesRequiredReturn(usize::MAX), 100);
    let tb2 = TestBreaker::new(TestBreakerBehaviour::BytesRequiredReturn(1), 200);

    let refs: [&dyn BytesRequired; 2] = [
        to_bytes_required_dyn_ref(&tb1),
        to_bytes_required_dyn_ref(&tb2),
    ];

    let result = bytes_required_sum(refs.into_iter());

    assert!(result.is_err());
}

// encode_fields

#[test]
fn test_encode_fields_ok() {
    let mut tb1 = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let mut tb2 = TestBreaker::new(TestBreakerBehaviour::None, 200);
    let mut buf = Buffer::new(1024);

    let refs: [&mut dyn EncodeZeroize; 2] = [
        to_encode_zeroize_dyn_mut(&mut tb1),
        to_encode_zeroize_dyn_mut(&mut tb2),
    ];

    let result = encode_fields(refs.into_iter(), &mut buf);

    assert!(result.is_ok());
}

#[test]
fn test_encode_fields_propagates_error() {
    let mut tb1 = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let mut tb2 = TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 200);
    let mut buf = Buffer::new(1024);

    let refs: [&mut dyn EncodeZeroize; 2] = [
        to_encode_zeroize_dyn_mut(&mut tb1),
        to_encode_zeroize_dyn_mut(&mut tb2),
    ];

    let result = encode_fields(refs.into_iter(), &mut buf);

    assert!(result.is_err());

    // Assert zeroization!
    #[cfg(feature = "zeroize")]
    {
        assert!(tb1.is_zeroized());
        assert!(tb2.is_zeroized());
        assert!(buf.is_zeroized());
    }
}

// decode_fields

#[test]
fn test_decode_fields_ok() {
    // First encode
    let mut tb1 = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let mut tb2 = TestBreaker::new(TestBreakerBehaviour::None, 200);
    let mut buf = Buffer::new(1024);

    let encode_refs: [&mut dyn EncodeZeroize; 2] = [
        to_encode_zeroize_dyn_mut(&mut tb1),
        to_encode_zeroize_dyn_mut(&mut tb2),
    ];
    encode_fields(encode_refs.into_iter(), &mut buf).expect("Failed to encode");

    // Decode
    let mut decoded1 = TestBreaker::default();
    let mut decoded2 = TestBreaker::default();

    let decode_refs: [&mut dyn DecodeZeroize; 2] = [
        to_decode_zeroize_dyn_mut(&mut decoded1),
        to_decode_zeroize_dyn_mut(&mut decoded2),
    ];

    let result = decode_fields(decode_refs.into_iter(), &mut buf.as_mut_slice());

    assert!(result.is_ok());
    assert_eq!(decoded1.data, 100);
    assert_eq!(decoded2.data, 200);
}

#[test]
fn test_decode_fields_propagates_error() {
    let mut decoded1 = TestBreaker::default();
    let mut decoded2 = TestBreaker::default();
    let mut buf = [0u8; 1]; // Too small

    let decode_refs: [&mut dyn DecodeZeroize; 2] = [
        to_decode_zeroize_dyn_mut(&mut decoded1),
        to_decode_zeroize_dyn_mut(&mut decoded2),
    ];

    let mut slice = buf.as_mut_slice();
    let result = decode_fields(decode_refs.into_iter(), &mut slice);

    assert!(result.is_err());

    // Assert zeroization!
    #[cfg(feature = "zeroize")]
    {
        assert!(decoded1.is_zeroized());
        assert!(decoded2.is_zeroized());
        assert!(slice.iter().all(|&b| b == 0));
    }
}
