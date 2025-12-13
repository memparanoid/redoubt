// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::codec_buffer::CodecBuffer;
use memzer::{FastZeroizable, ZeroizationProbe};

use crate::error::{DecodeError, EncodeError};
use crate::support::test_utils::{CodecTestBreaker, CodecTestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, DecodeSlice, Encode, PreAlloc};

// CodecTestBreakerBehaviour

#[test]
fn test_behaviour_default() {
    let behaviour = CodecTestBreakerBehaviour::default();
    assert_eq!(behaviour, CodecTestBreakerBehaviour::None);
}

// CodecTestBreaker

#[test]
fn test_default() {
    let tb = CodecTestBreaker::default();
    assert_eq!(tb.behaviour, CodecTestBreakerBehaviour::None);
    assert_eq!(tb.usize.data, 104729);
}

#[test]
fn test_new() {
    let tb = CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceEncodeError, 512);
    assert_eq!(tb.behaviour, CodecTestBreakerBehaviour::ForceEncodeError);
    assert_eq!(tb.usize.data, 512);
}

#[test]
fn test_zeroization() {
    let mut tb = CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceEncodeError, 512);

    assert!(!tb.is_zeroized());
    tb.fast_zeroize();

    assert!(tb.is_zeroized());
}

#[test]
fn test_with_behaviour() {
    let tb = CodecTestBreaker::with_behaviour(CodecTestBreakerBehaviour::ForceEncodeError);
    assert_eq!(tb.behaviour, CodecTestBreakerBehaviour::ForceEncodeError);
    assert_eq!(tb.usize.data, 104729);
}

#[test]
fn test_set_behaviour() {
    let mut tb = CodecTestBreaker::default();
    assert_eq!(tb.behaviour, CodecTestBreakerBehaviour::None);

    tb.set_behaviour(CodecTestBreakerBehaviour::ForceDecodeError);
    assert_eq!(tb.behaviour, CodecTestBreakerBehaviour::ForceDecodeError);
}

#[test]
fn test_is_zeroized() {
    let mut tb = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100);
    assert!(!tb.is_zeroized());

    tb.fast_zeroize();

    assert!(tb.is_zeroized());
}

// BytesRequired

#[test]
fn test_bytes_required_return_max() {
    let tb = CodecTestBreaker::with_behaviour(CodecTestBreakerBehaviour::BytesRequiredReturnMax);
    assert_eq!(
        tb.mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
        usize::MAX
    );
}

#[test]
fn test_bytes_required_return_specific() {
    let tb = CodecTestBreaker::with_behaviour(CodecTestBreakerBehaviour::BytesRequiredReturn(42));
    assert_eq!(
        tb.mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
        42
    );
}

#[test]
fn test_bytes_required_overflow() {
    let tb = CodecTestBreaker::with_behaviour(CodecTestBreakerBehaviour::ForceBytesRequiredOverflow);
    assert!(tb.mem_bytes_required().is_err());
}

// Encode

#[test]
fn test_force_encode_error() {
    let mut tb = CodecTestBreaker::with_behaviour(CodecTestBreakerBehaviour::ForceEncodeError);
    let mut buf = CodecBuffer::new(1024);

    let result = tb.encode_into(&mut buf);
    assert!(matches!(result, Err(EncodeError::IntentionalEncodeError)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
    }
}

// Decode

#[test]
fn test_force_decode_error() {
    let mut tb = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100);
    let bytes_required = tb
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    let mut buf = CodecBuffer::new(bytes_required);
    tb.encode_into(&mut buf).expect("Failed to encode_into(..)");

    let mut decode_buf = buf.export_as_vec();
    let mut tb_decode = CodecTestBreaker::with_behaviour(CodecTestBreakerBehaviour::ForceDecodeError);
    let result = tb_decode.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
    }
}

// Roundtrip (Encode + Decode)

#[test]
fn test_roundtrip() {
    let mut original = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 256);
    let original_usize = original.usize;

    let bytes_required = original
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);
    original
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut decode_buf = buf.export_as_vec();
    let mut decoded = CodecTestBreaker::default();
    decoded
        .decode_from(&mut decode_buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    assert_eq!(decoded.usize, original_usize);

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(original.is_zeroized());
    }
}

// EncodeSlice

#[test]
fn test_encode_slice_error() {
    let mut vec = vec![
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 10),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceEncodeError, 10),
    ];
    let mut buf = CodecBuffer::new(1024);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
}

// DecodeSlice

#[test]
fn test_decode_slice_error() {
    let mut vec = vec![
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceDecodeError, 100),
    ];
    let mut buf = [0u8];

    let result = CodecTestBreaker::decode_slice_from(vec.as_mut_slice(), &mut buf.as_mut_slice());

    assert!(result.is_err());
}

// PreAlloc

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_zero_init_is_false() {
    assert!(!CodecTestBreaker::ZERO_INIT);
}

#[test]
fn test_prealloc() {
    let mut tb = CodecTestBreaker::default();
    assert_eq!(tb.usize.data, 104729);

    // PreAlloc is no-op for CodecTestBreaker (ZERO_INIT = false)
    tb.prealloc(999);

    // Data should remain unchanged
    assert_eq!(tb.usize.data, 104729);
    assert_eq!(tb.behaviour, CodecTestBreakerBehaviour::None);
}
