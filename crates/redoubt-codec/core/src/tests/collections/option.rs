// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError, RedoubtCodecBufferError};
use crate::support::test_utils::{RedoubtCodecTestBreaker, RedoubtCodecTestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, Encode};

#[cfg(feature = "zeroize")]
use redoubt_zero::ZeroizationProbe;

// Bytes Required

#[test]
fn test_bytes_required_none() {
    let opt: Option<RedoubtCodecTestBreaker> = None;
    let bytes_required = opt
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    assert_eq!(bytes_required, 2 * size_of::<usize>());
}

#[test]
fn test_bytes_required_some() {
    let opt = Some(RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        42,
    ));
    let bytes_required = opt
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    // Header (2 * usize) + RedoubtCodecTestBreaker (2 * usize)
    let expected = 4 * size_of::<usize>();
    assert_eq!(bytes_required, expected);
}

#[test]
fn test_bytes_required_propagates_overflow_error() {
    let opt = Some(RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
        200,
    ));

    let result = opt.encode_bytes_required();

    assert!(result.is_err());
    assert!(matches!(result, Err(OverflowError { .. })));
}

#[test]
fn test_bytes_required_reports_overflow_error() {
    let opt = Some(RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::BytesRequiredReturnMax,
        200,
    ));

    let result = opt.encode_bytes_required();

    assert!(result.is_err());
    assert!(matches!(result, Err(OverflowError { .. })));
}

// Encode

#[test]
fn test_encode_into_propagates_bytes_required_error() {
    let mut opt = Some(RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    ));
    let enough_bytes_required = 1024;
    let mut buf = RedoubtCodecBuffer::with_capacity(enough_bytes_required);

    let result = opt.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::OverflowError(OverflowError { .. }))
    ));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert_eq!(opt, None);
        assert!(buf.is_zeroized());
    }
}

#[test]
fn test_encode_propagates_capacity_exceeded_error_none() {
    let mut opt: Option<RedoubtCodecTestBreaker> = None;
    let mut buf = RedoubtCodecBuffer::with_capacity(0);

    let result = opt.encode_into(&mut buf);

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
        assert_eq!(opt, None);
        assert!(buf.is_zeroized());
    }
}

#[test]
fn test_encode_propagates_capacity_exceeded_error_some() {
    let mut opt = Some(RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        42,
    ));
    let mut buf = RedoubtCodecBuffer::with_capacity(0);

    let result = opt.encode_into(&mut buf);

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
        assert_eq!(opt, None);
        assert!(buf.is_zeroized());
    }
}

// Decode

#[test]
fn test_option_decode_from_propagates_process_header_err() {
    let mut opt: Option<RedoubtCodecTestBreaker> = None;
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small for header

    let mut decode_buf = buf.export_as_vec();
    let result = opt.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert_eq!(opt, None);
    }
}

#[test]
fn test_option_decode_from_propagates_invalid_size_value() {
    let mut opt: Option<RedoubtCodecTestBreaker> = None;

    // Create a buffer with invalid size value (2, should be 0 or 1)
    let mut buf = RedoubtCodecBuffer::with_capacity(1024);
    let mut size = 2usize;
    let mut bytes_required = 2 * size_of::<usize>();
    buf.write(&mut size)
        .expect("Failed to write size to buffer");
    buf.write(&mut bytes_required)
        .expect("Failed to write bytes_required to buffer");

    let mut decode_buf = buf.export_as_vec();
    let result = opt.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert_eq!(opt, None);
        assert!(decode_buf.is_zeroized());
    }
}

// Note: Unlike Vec, we cannot test `test_option_decode_from_propagates_decode_err` because
// Option always creates a fresh T::default() when decoding Some(_), so there's no way to
// inject a RedoubtCodecTestBreaker with ForceDecodeError behaviour that would survive into
// the decode path.

#[test]
fn test_option_decode_from_truncated_buffer() {
    let mut original = Some(RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        99,
    ));

    let bytes_required = original
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);
    original
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut decoded: Option<RedoubtCodecTestBreaker> = None;
    let mut decode_buf = buf.export_as_vec();
    let mut slice = &mut decode_buf.as_mut_slice()[..bytes_required - 1];
    let result = decoded.decode_from(&mut slice);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert_eq!(decoded, None);
        assert!(slice.is_zeroized());
    }
}

// Roundtrip

#[test]
fn test_option_encode_decode_roundtrip_none() {
    // Encode
    let mut opt: Option<RedoubtCodecTestBreaker> = None;
    let bytes_required = opt
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    opt.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    {
        let mut decode_buf = buf.export_as_vec();
        let mut recovered = Some(RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            999,
        ));
        let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

        assert!(result.is_ok());
        assert_eq!(recovered, None);

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
        assert_eq!(opt, None);
    }
}

#[test]
fn test_option_encode_decode_roundtrip_some() {
    // Encode
    let mut opt = Some(RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        42,
    ));
    let bytes_required = opt
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    opt.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    {
        let mut decode_buf = buf.export_as_vec();
        let mut recovered = None;
        let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

        assert!(result.is_ok());
        assert_eq!(
            recovered,
            Some(RedoubtCodecTestBreaker::new(
                RedoubtCodecTestBreakerBehaviour::None,
                42
            ))
        );

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
        assert_eq!(opt, None);
    }
}
