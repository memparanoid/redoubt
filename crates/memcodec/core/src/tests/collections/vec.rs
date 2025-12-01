// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;
use memzer::ZeroizationProbe;

use crate::support::test_utils::{TestBreaker, TestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, DecodeSlice, Encode, EncodeSlice};

use super::utils::test_collection_varying_capacities;

#[test]
fn test_vec_test_breaker_varying_capacities() {
    let set: Vec<_> = (0..250)
        .map(|i| TestBreaker::new(TestBreakerBehaviour::None, i))
        .collect();

    test_collection_varying_capacities(
        &set,
        |cap| Vec::with_capacity(cap),
        |vec, slice| {
            vec.clear();
            vec.extend_from_slice(slice);
        },
        |a, b| a == b,
    );
}

// BytesRequired

#[test]
fn test_bytes_required_element_error() {
    let vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 10),
        TestBreaker::new(TestBreakerBehaviour::ForceBytesRequiredOverflow, 10),
    ];
    assert!(vec.mem_bytes_required().is_err());
}

#[test]
fn test_bytes_required_overflow() {
    let vec = vec![
        TestBreaker::new(TestBreakerBehaviour::BytesRequiredReturnMax, 10),
        TestBreaker::new(TestBreakerBehaviour::BytesRequiredReturn(1), 10),
    ];
    assert!(vec.mem_bytes_required().is_err());
}

// Encode

#[test]
fn test_encode_bytes_required_error() {
    let mut vec = vec![TestBreaker::new(TestBreakerBehaviour::ForceBytesRequiredOverflow, 10)];
    let mut buf = Buffer::new(1024);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
}

#[test]
fn test_encode_buffer_too_small() {
    let mut vec = vec![TestBreaker::new(TestBreakerBehaviour::None, 100)];
    let mut buf = Buffer::new(1); // Too small

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
}

#[test]
fn test_encode_element_error() {
    let mut vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 10),
        TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 10),
    ];
    let mut buf = Buffer::new(1024);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
    // Assert zeroization!
    assert!(vec.iter().all(|tb| tb.is_zeroized()));
    assert!(buf.is_zeroized());
}

// EncodeSlice

#[test]
fn test_encode_slice_ok() {
    let mut slice = [
        vec![TestBreaker::new(TestBreakerBehaviour::None, 10)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 10)],
    ];
    let mut buf = Buffer::new(1024);

    let result = Vec::<TestBreaker>::encode_slice_into(&mut slice, &mut buf);

    assert!(result.is_ok());
}

#[test]
fn test_encode_slice_error() {
    let mut slice = [
        vec![TestBreaker::new(TestBreakerBehaviour::None, 10)],
        vec![TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 10)],
    ];
    let mut buf = Buffer::new(1024);

    let result = Vec::<TestBreaker>::encode_slice_into(&mut slice, &mut buf);

    assert!(result.is_err());
}

// Decode

#[test]
fn test_decode_buffer_too_small() {
    let mut vec: Vec<TestBreaker> = Vec::new();
    let mut buf = [0u8; 1];

    let result = vec.decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
}

#[test]
fn test_decode_element_error() {
    // First encode valid data
    let mut vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 100),
    ];
    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Truncate buffer to make second element fail
    let truncated = bytes_required / 2;
    let mut decoded: Vec<TestBreaker> = Vec::new();
    let mut slice = &mut buf.as_mut_slice()[..truncated];

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
        vec![TestBreaker::new(TestBreakerBehaviour::None, 10)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 10)],
    ];
    let mut buf = Buffer::new(1024);
    Vec::<TestBreaker>::encode_slice_into(&mut slice, &mut buf)
        .expect("Failed to encode_slice_into(..)");

    // Decode
    let mut decoded: [Vec<TestBreaker>; 2] = [Vec::new(), Vec::new()];

    let result = Vec::<TestBreaker>::decode_slice_from(&mut decoded, &mut buf.as_mut_slice());

    assert!(result.is_ok());
}

#[test]
fn test_decode_slice_error() {
    let mut slice = [
        vec![TestBreaker::new(TestBreakerBehaviour::None, 10)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 10)],
    ];
    let mut buf = [0u8];

    let result = Vec::<TestBreaker>::decode_slice_from(&mut slice, &mut buf.as_mut_slice());

    assert!(result.is_err());
}
