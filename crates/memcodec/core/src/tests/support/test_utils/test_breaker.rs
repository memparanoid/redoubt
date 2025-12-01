// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::error::{DecodeError, EncodeError};
use crate::support::test_utils::{TestBreaker, TestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, DecodeSlice, Encode, PreAlloc};

// TestBreakerBehaviour

#[test]
fn test_behaviour_default() {
    let behaviour = TestBreakerBehaviour::default();
    assert_eq!(behaviour, TestBreakerBehaviour::None);
}

// TestBreaker

#[test]
fn test_default() {
    let tb = TestBreaker::default();
    assert_eq!(tb.behaviour, TestBreakerBehaviour::None);
    assert_eq!(tb.data, 104729);
}

#[test]
fn test_new() {
    let tb = TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 512);
    assert_eq!(tb.behaviour, TestBreakerBehaviour::ForceEncodeError);
    assert_eq!(tb.data, 512);
}

#[test]
fn test_with_behaviour() {
    let tb = TestBreaker::with_behaviour(TestBreakerBehaviour::ForceEncodeError);
    assert_eq!(tb.behaviour, TestBreakerBehaviour::ForceEncodeError);
    assert_eq!(tb.data, 104729);
}

#[test]
fn test_set_behaviour() {
    let mut tb = TestBreaker::default();
    assert_eq!(tb.behaviour, TestBreakerBehaviour::None);

    tb.set_behaviour(TestBreakerBehaviour::ForceDecodeError);
    assert_eq!(tb.behaviour, TestBreakerBehaviour::ForceDecodeError);
}

#[test]
fn test_is_zeroized() {
    let mut tb = TestBreaker::new(TestBreakerBehaviour::None, 100);
    assert!(!tb.is_zeroized());

    tb.data = 0;
    assert!(tb.is_zeroized());
}

// BytesRequired

#[test]
fn test_bytes_required_return_max() {
    let tb = TestBreaker::with_behaviour(TestBreakerBehaviour::BytesRequiredReturnMax);
    assert_eq!(
        tb.mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
        usize::MAX
    );
}

#[test]
fn test_bytes_required_return_specific() {
    let tb = TestBreaker::with_behaviour(TestBreakerBehaviour::BytesRequiredReturn(42));
    assert_eq!(
        tb.mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
        42
    );
}

#[test]
fn test_bytes_required_overflow() {
    let tb = TestBreaker::with_behaviour(TestBreakerBehaviour::ForceBytesRequiredOverflow);
    assert!(tb.mem_bytes_required().is_err());
}

// Encode

#[test]
fn test_force_encode_error() {
    let mut tb = TestBreaker::with_behaviour(TestBreakerBehaviour::ForceEncodeError);
    let mut buf = Buffer::new(1024);

    let result = tb.encode_into(&mut buf);
    assert!(matches!(result, Err(EncodeError::IntentionalEncodeError)));
}

// Decode

#[test]
fn test_force_decode_error() {
    // First encode a valid TestBreaker
    let mut tb = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let bytes_required = tb
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    tb.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Now try to decode with ForceDecodeError
    let mut tb_decode = TestBreaker::with_behaviour(TestBreakerBehaviour::ForceDecodeError);
    let result = tb_decode.decode_from(&mut buf.as_mut_slice());
    assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));
}

// Roundtrip (Encode + Decode)

#[test]
fn test_roundtrip() {
    let mut original = TestBreaker::new(TestBreakerBehaviour::None, 256);
    let original_data = original.data;

    let bytes_required = original
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    original
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut decoded = TestBreaker::default();
    decoded
        .decode_from(&mut buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    assert_eq!(decoded.data, original_data);
}

// EncodeSlice

#[test]
fn test_encode_slice_error() {
    let mut vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 10),
        TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 10),
    ];
    let mut buf = Buffer::new(1024);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
}

// DecodeSlice

#[test]
fn test_decode_slice_error() {
    let mut vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::ForceDecodeError, 100),
    ];
    let mut buf = [0u8];

    let result = TestBreaker::decode_slice_from(vec.as_mut_slice(), &mut buf.as_mut_slice());

    assert!(result.is_err());
}

// PreAlloc

#[test]
fn test_zero_init_is_false() {
    assert!(!TestBreaker::ZERO_INIT);
}

#[test]
fn test_prealloc() {
    let mut tb = TestBreaker::default();
    assert_eq!(tb.data, 104729);

    // PreAlloc is no-op for TestBreaker (ZERO_INIT = false)
    tb.prealloc(999);

    // Data should remain unchanged
    assert_eq!(tb.data, 104729);
    assert_eq!(tb.behaviour, TestBreakerBehaviour::None);
}
