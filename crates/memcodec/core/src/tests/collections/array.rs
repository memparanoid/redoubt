// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;
use memzer::ZeroizationProbe;

use crate::error::OverflowError;
use crate::support::test_utils::{TestBreaker, TestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice};

// BytesRequired

#[test]
fn test_bytes_required_element_error() {
    let arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 10),
        TestBreaker::new(TestBreakerBehaviour::ForceBytesRequiredOverflow, 10),
    ];

    let result = arr.mem_bytes_required();

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(OverflowError { reason }) if reason == "TestBreaker forced overflow"
    ));
}

#[test]
fn test_bytes_required_overflow() {
    // Two elements each returning usize::MAX / 2 will overflow on the second iteration
    let arr = [
        TestBreaker::new(
            TestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
        TestBreaker::new(
            TestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
    ];

    let result = arr.mem_bytes_required();

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(OverflowError { reason }) if reason == "Array bytes_required overflow"
    ));
}

// Encode

#[test]
fn test_encode_bytes_required_error() {
    let mut arr = [TestBreaker::new(
        TestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    )];
    let mut buf = Buffer::new(1024);

    let result = arr.encode_into(&mut buf);

    assert!(result.is_err());
}

#[test]
fn test_encode_buffer_too_small() {
    let mut arr = [TestBreaker::new(TestBreakerBehaviour::None, 100)];
    let mut buf = Buffer::new(1); // Too small

    let result = arr.encode_into(&mut buf);

    assert!(result.is_err());
}

#[test]
fn test_encode_element_error() {
    let mut arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 10),
        TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 10),
    ];
    let mut buf = Buffer::new(1024);

    let result = arr.encode_into(&mut buf);

    assert!(result.is_err());

    // Assert zeroization!
    assert!(arr.iter().all(|tb| tb.is_zeroized()));
    assert!(buf.is_zeroized());
}

// EncodeSlice

#[test]
fn test_encode_slice_ok() {
    let mut slice = [
        [TestBreaker::new(TestBreakerBehaviour::None, 10)],
        [TestBreaker::new(TestBreakerBehaviour::None, 10)],
    ];
    let mut buf = Buffer::new(1024);

    let result = <[TestBreaker; 1]>::encode_slice_into(&mut slice, &mut buf);

    assert!(result.is_ok());
}

#[test]
fn test_encode_slice_propagates_encode_into_error() {
    let mut slice = [
        [TestBreaker::new(TestBreakerBehaviour::None, 10)],
        [TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 10)],
    ];
    let mut buf = Buffer::new(1024);

    let result = <[TestBreaker; 1]>::encode_slice_into(&mut slice, &mut buf);

    assert!(result.is_err());
}

// Decode

#[test]
fn test_decode_buffer_too_small() {
    let mut arr: [TestBreaker; 1] = [TestBreaker::default()];
    let mut buf = [0u8; 1];

    let result = arr.decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
}

#[test]
fn test_decode_size_mismatch() {
    // Encode array of size 2
    let mut arr2 = [
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 100),
    ];
    let bytes_required = arr2
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    arr2.encode_into(&mut buf).expect("Failed to encode_into(..)");

    // Try to decode into array of size 1
    let mut arr1: [TestBreaker; 1] = [TestBreaker::default()];
    let result = arr1.decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
}

#[test]
fn test_decode_element_error() {
    // First encode valid data
    let mut arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 100),
    ];
    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    arr.encode_into(&mut buf).expect("Failed to encode_into(..)");

    // Truncate buffer to make second element fail
    let insufficient_bytes_required = bytes_required / 2;
    let mut decoded: [TestBreaker; 2] = [TestBreaker::default(), TestBreaker::default()];
    let mut slice = &mut buf.as_mut_slice()[..insufficient_bytes_required];

    let result = decoded.decode_from(&mut slice);

    assert!(result.is_err());

    // Assert zeroization!
    assert!(decoded.iter().all(|tb| tb.is_zeroized()));
    assert!(slice.iter().all(|&b| b == 0));
}

// DecodeSlice

#[test]
fn test_decode_slice_ok() {
    // First encode valid data
    let mut slice = [
        [TestBreaker::new(TestBreakerBehaviour::None, 10)],
        [TestBreaker::new(TestBreakerBehaviour::None, 10)],
    ];
    let mut buf = Buffer::new(1024);
    <[TestBreaker; 1]>::encode_slice_into(&mut slice, &mut buf)
        .expect("Failed to encode_slice_into(..)");

    // Decode
    let mut decoded: [[TestBreaker; 1]; 2] = [[TestBreaker::default()], [TestBreaker::default()]];

    let result = <[TestBreaker; 1]>::decode_slice_from(&mut decoded, &mut buf.as_mut_slice());

    assert!(result.is_ok());
}

#[test]
fn test_decode_slice_propagates_decode_from_error() {
    let mut slice = [
        [TestBreaker::new(TestBreakerBehaviour::None, 10)],
        [TestBreaker::new(TestBreakerBehaviour::None, 10)],
    ];
    let mut buf = [0u8];

    let result = <[TestBreaker; 1]>::decode_slice_from(&mut slice, &mut buf.as_mut_slice());

    assert!(result.is_err());
}
