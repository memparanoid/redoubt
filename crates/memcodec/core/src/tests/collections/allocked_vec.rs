// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memalloc::AllockedVec;
use membuffer::Buffer;
use memzer::ZeroizationProbe;

use crate::collections::helpers::header_size;
use crate::error::OverflowError;
use crate::support::test_utils::{TestBreaker, TestBreakerBehaviour};
use crate::traits::{BytesRequired, CodecBuffer, Decode, DecodeSlice, Encode, EncodeSlice};

// BytesRequired

#[test]
fn test_bytes_required_element_error() {
    let mut vec = AllockedVec::with_capacity(2);
    vec.push(TestBreaker::new(TestBreakerBehaviour::None, 10))
        .expect("Failed to push(..)");
    vec.push(TestBreaker::new(
        TestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    ))
    .expect("Failed to push(..)");

    let result = vec.mem_bytes_required();

    assert!(result.is_err());
    match result {
        Err(OverflowError { reason }) => {
            assert_eq!(reason, "TestBreaker forced overflow");
        }
        _ => panic!("Expected OverflowError"),
    }
}

#[test]
fn test_bytes_required_overflow() {
    // Two elements each returning usize::MAX / 2 will overflow on the second iteration
    let mut vec = AllockedVec::with_capacity(2);
    vec.push(TestBreaker::new(
        TestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
        10,
    ))
    .expect("Failed to push(..)");
    vec.push(TestBreaker::new(
        TestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
        10,
    ))
    .expect("Failed to push(..)");

    let result = vec.mem_bytes_required();

    assert!(result.is_err());
    match result {
        Err(OverflowError { reason }) => {
            assert_eq!(reason, "AllockedVec bytes_required overflow");
        }
        _ => panic!("Expected OverflowError"),
    }
}

// Encode

#[test]
fn test_encode_bytes_required_error() {
    let mut vec = AllockedVec::with_capacity(1);
    vec.push(TestBreaker::new(
        TestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    ))
    .expect("Failed to push(..)");
    let mut buf = Buffer::new(1024);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
}

#[test]
fn test_encode_buffer_too_small() {
    let mut vec = AllockedVec::with_capacity(1);
    vec.push(TestBreaker::new(TestBreakerBehaviour::None, 100))
        .expect("Failed to push(..)");
    let mut buf = Buffer::new(1); // Too small

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
}

#[test]
fn test_encode_element_error() {
    let mut vec = AllockedVec::with_capacity(2);
    vec.push(TestBreaker::new(TestBreakerBehaviour::None, 10))
        .expect("Failed to push(..)");
    vec.push(TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 10))
        .expect("Failed to push(..)");
    let mut buf = Buffer::new(1024);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());

    // Assert zeroization!
    assert!(vec.as_slice().iter().all(|tb| tb.is_zeroized()));
    assert!(buf.is_zeroized());
}

// EncodeSlice

#[test]
fn test_encode_slice_ok() {
    let mut vec1 = AllockedVec::with_capacity(1);
    vec1.push(TestBreaker::new(TestBreakerBehaviour::None, 10))
        .expect("Failed to push(..)");
    let mut vec2 = AllockedVec::with_capacity(1);
    vec2.push(TestBreaker::new(TestBreakerBehaviour::None, 10))
        .expect("Failed to push(..)");
    let mut slice = [vec1, vec2];
    let mut buf = Buffer::new(1024);

    let result = AllockedVec::<TestBreaker>::encode_slice_into(&mut slice, &mut buf);

    assert!(result.is_ok());
}

#[test]
fn test_encode_slice_propagates_encode_into_error() {
    let mut vec1 = AllockedVec::with_capacity(1);
    vec1.push(TestBreaker::new(TestBreakerBehaviour::None, 10))
        .expect("Failed to push(..)");
    let mut vec2 = AllockedVec::with_capacity(1);
    vec2.push(TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 10))
        .expect("Failed to push(..)");
    let mut slice = [vec1, vec2];
    let mut buf = Buffer::new(1024);

    let result = AllockedVec::<TestBreaker>::encode_slice_into(&mut slice, &mut buf);

    assert!(result.is_err());
}

// Decode

#[test]
fn test_decode_buffer_too_small() {
    let mut vec: AllockedVec<TestBreaker> = AllockedVec::new();
    let mut buf = [0u8; 1];

    let result = vec.decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
}

#[test]
fn test_decode_element_error() {
    // First encode valid data
    let mut vec = AllockedVec::with_capacity(2);
    vec.push(TestBreaker::new(TestBreakerBehaviour::None, 100))
        .expect("Failed to push(..)");
    vec.push(TestBreaker::new(TestBreakerBehaviour::None, 100))
        .expect("Failed to push(..)");
    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Truncate buffer to make second element fail
    let insufficient_bytes_required = bytes_required / 2;
    let mut decoded: AllockedVec<TestBreaker> = AllockedVec::new();
    let mut slice = &mut buf.as_mut_slice()[..insufficient_bytes_required];

    let result = decoded.decode_from(&mut slice);

    assert!(result.is_err());

    // Assert zeroization!
    assert!(decoded.as_slice().iter().all(|tb| tb.is_zeroized()));
    assert!(slice.iter().all(|&b| b == 0));
}

// DecodeSlice

#[test]
fn test_decode_slice_ok() {
    // First encode valid data
    let mut vec1 = AllockedVec::with_capacity(1);
    vec1.push(TestBreaker::new(TestBreakerBehaviour::None, 10))
        .expect("Failed to push(..)");
    let mut vec2 = AllockedVec::with_capacity(1);
    vec2.push(TestBreaker::new(TestBreakerBehaviour::None, 10))
        .expect("Failed to push(..)");
    let mut slice = [vec1, vec2];
    let mut buf = Buffer::new(1024);
    AllockedVec::<TestBreaker>::encode_slice_into(&mut slice, &mut buf)
        .expect("Failed to encode_slice_into(..)");

    // Decode
    let mut decoded: [AllockedVec<TestBreaker>; 2] = [AllockedVec::new(), AllockedVec::new()];

    let result =
        AllockedVec::<TestBreaker>::decode_slice_from(&mut decoded, &mut buf.as_mut_slice());

    assert!(result.is_ok());
}

#[test]
fn test_decode_slice_propagates_decode_from_error() {
    let mut vec1 = AllockedVec::with_capacity(1);
    vec1.push(TestBreaker::new(TestBreakerBehaviour::None, 10))
        .expect("Failed to push(..)");
    let mut vec2 = AllockedVec::with_capacity(1);
    vec2.push(TestBreaker::new(TestBreakerBehaviour::None, 10))
        .expect("Failed to push(..)");
    let mut slice = [vec1, vec2];
    let mut buf = [0u8];

    let result =
        AllockedVec::<TestBreaker>::decode_slice_from(&mut slice, &mut buf.as_mut_slice());

    assert!(result.is_err());
}

// Integration test

/// Tests that AllockedVec decode correctly resets to the encoded size,
/// regardless of the initial capacity or content of the destination vector.
#[test]
fn test_allocked_vec_encode_decode_with_varying_capacities() {
    let max_elements = u8::MAX as usize;

    for i in 0..max_elements {
        // Create original vector with `i` elements
        let mut original_vec = AllockedVec::with_capacity(i);
        let mut original_vec_clone = AllockedVec::with_capacity(i);

        let data = vec![u8::MAX; i];
        original_vec
            .drain_from(data.clone().as_mut_slice())
            .expect("Failed to drain_from(..)");
        original_vec_clone
            .drain_from(data.clone().as_mut_slice())
            .expect("Failed to drain_from(..)");

        // Encode
        let bytes_required = original_vec_clone
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        let mut buf = Buffer::new(bytes_required);

        original_vec_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        assert_eq!(buf.as_slice().len(), header_size() + i);

        // Test decode with various initial capacities (smaller, equal, and larger than encoded size)
        for j in 0..i * 2 {
            let mut recovered_vec = AllockedVec::<u8>::with_capacity(j);

            let mut buf_clone = Buffer::new(buf.as_slice().len());
            buf_clone
                .write_slice(buf.as_slice().to_vec().as_mut_slice())
                .expect("Failed to write_slice(..)");

            // Pre-fill recovered_vec with garbage data to verify decode overwrites it completely
            {
                let mut data = vec![u8::MAX; j];
                recovered_vec
                    .drain_from(data.as_mut_slice())
                    .expect("Failed to drain_from(..)");
            }

            recovered_vec
                .decode_from(&mut buf_clone.as_mut_slice())
                .expect("Failed to decode_from(..)");

            // After decode, recovered_vec must exactly match original_vec
            // regardless of its initial capacity `j`
            assert_eq!(original_vec.capacity(), recovered_vec.capacity());
            assert_eq!(original_vec.len(), recovered_vec.len());
            assert_eq!(original_vec.as_slice(), recovered_vec.as_slice());
        }
    }
}
