// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::AllockedVec;
use redoubt_test_utils::{apply_permutation, index_permutations};
use redoubt_zero::ZeroizationProbe;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::error::{DecodeError, EncodeError, OverflowError, RedoubtCodecBufferError};
use crate::support::test_utils::{RedoubtCodecTestBreaker, RedoubtCodecTestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, Encode, PreAlloc};

fn make_allocked_vec(items: &[RedoubtCodecTestBreaker]) -> AllockedVec<RedoubtCodecTestBreaker> {
    let mut vec = AllockedVec::with_capacity(items.len());
    for item in items {
        vec.push(*item).expect("push");
    }
    vec
}

// Bytes Required

#[test]
fn test_bytes_required_propagates_overflow_error() {
    let vec = make_allocked_vec(&[
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 10),
        RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
            10,
        ),
    ]);

    let result = vec.encode_bytes_required();

    assert!(result.is_err());
    match result {
        Err(OverflowError { reason }) => {
            assert_eq!(reason, "RedoubtCodecTestBreaker forced overflow");
        }
        _ => panic!("Expected OverflowError"),
    }
}

#[test]
fn test_bytes_required_reports_overflow_error() {
    // Two elements each returning usize::MAX / 2 will overflow on the second iteration
    let vec = make_allocked_vec(&[
        RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
        RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
    ]);

    let result = vec.encode_bytes_required();

    assert!(result.is_err());
    assert!(matches!(result, Err(OverflowError { .. })));
}

// Encode

#[test]
fn test_encode_into_propagates_bytes_required_error() {
    let mut vec = make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    )]);
    let enough_bytes_required = 1024;
    let mut buf = RedoubtCodecBuffer::with_capacity(enough_bytes_required);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(EncodeError::OverflowError(_))));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(vec.as_slice().is_zeroized());
    }
}

#[test]
fn test_encode_propagates_capacity_exceeded_error() {
    let mut vec = make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        100,
    )]);
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small

    let result = vec.encode_into(&mut buf);

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
        assert!(vec.as_slice().is_zeroized());
    }
}

// Decode

#[test]
fn test_allocked_vec_decode_from_propagates_process_header_err() {
    let mut vec: AllockedVec<RedoubtCodecTestBreaker> = AllockedVec::new();
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small for header

    let mut decode_buf = buf.export_as_vec();
    let result = vec.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(vec.is_zeroized());
    }
}

#[test]
fn test_allocked_vec_decode_propagates_decode_err() {
    let mut vec = make_allocked_vec(&[
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100),
    ]);
    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut recovered = make_allocked_vec(&[
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceDecodeError, 100),
    ]);

    let mut decode_buf = buf.export_as_vec();
    let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(vec.is_zeroized());
        assert!(recovered.is_zeroized());
    }
}

// Roundtrip

#[test]
fn test_allocked_vec_encode_decode_roundtrip() {
    // Encode
    let mut vec = make_allocked_vec(&[
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 7),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 37),
    ]);
    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    {
        let mut decode_buf = buf.export_as_vec();
        let mut recovered = make_allocked_vec(&[
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 0),
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 0),
        ]);
        let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

        assert!(result.is_ok());
        assert_eq!(
            recovered.as_slice(),
            &[
                RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 7),
                RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 37),
            ]
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
        assert!(vec.is_zeroized());
    }
}

// Perm tests

#[test]
fn perm_test_allocked_vec_encode_into_propagates_error_at_any_position() {
    let mut vec = AllockedVec::with_capacity(6);
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        1,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        2,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        3,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        4,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        5,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::ForceEncodeError,
        6,
    )]))
    .expect("Failed to push(..)");

    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");

    index_permutations(vec.len(), |idx_perm| {
        let mut vec_clone = vec.clone();
        apply_permutation(vec_clone.as_mut_slice(), idx_perm);

        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);
        let result = vec_clone.encode_into(&mut buf);

        assert!(result.is_err());
        assert!(matches!(result, Err(EncodeError::IntentionalEncodeError)));

        // Assert zeroization!
        #[cfg(feature = "zeroize")]
        {
            assert!(buf.is_zeroized());
            assert!(vec_clone.is_zeroized());
        }
    });
}

#[test]
fn perm_test_allocked_vec_decode_from_propagates_error_at_any_position() {
    let mut vec = AllockedVec::with_capacity(6);
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        1,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        2,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        3,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        4,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        5,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        6,
    )]))
    .expect("Failed to push(..)");

    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");

    let recovered_vec = {
        let mut recovered_vec = vec.clone();
        recovered_vec.as_mut_slice()[0].as_mut_slice()[0]
            .set_behaviour(RedoubtCodecTestBreakerBehaviour::ForceDecodeError);
        recovered_vec
    };

    index_permutations(vec.len(), |idx_perm| {
        // Encode
        let mut vec_clone = vec.clone();
        apply_permutation(vec_clone.as_mut_slice(), idx_perm);

        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);
        vec_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        {
            let mut recovered_vec_clone = recovered_vec.clone();
            apply_permutation(recovered_vec_clone.as_mut_slice(), idx_perm);

            let mut decode_buf = buf.export_as_vec();
            let result = recovered_vec_clone.decode_from(&mut decode_buf.as_mut_slice());

            assert!(result.is_err());
            assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

            #[cfg(feature = "zeroize")]
            // Assert zeroization!
            {
                assert!(buf.is_zeroized());
                assert!(decode_buf.is_zeroized());
                assert!(recovered_vec_clone.is_zeroized());
            }
        }

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(vec_clone.is_zeroized());
        }
    });
}

#[test]
fn perm_test_allocked_vec_encode_decode_roundtrip() {
    let mut vec: AllockedVec<AllockedVec<RedoubtCodecTestBreaker>> = AllockedVec::with_capacity(6);
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        1,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        2,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        3,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        4,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        5,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        6,
    )]))
    .expect("Failed to push(..)");

    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");

    index_permutations(vec.len(), |idx_perm| {
        let mut vec_clone = vec.clone();
        apply_permutation(vec_clone.as_mut_slice(), idx_perm);

        let expected = vec_clone.clone();

        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);
        vec_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        let mut decode_buf = buf.export_as_vec();
        let mut recovered: AllockedVec<AllockedVec<RedoubtCodecTestBreaker>> = AllockedVec::new();
        let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

        assert!(result.is_ok());
        assert_eq!(recovered, expected);

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(decode_buf.is_zeroized());
            assert!(vec_clone.is_zeroized());
        }
    });
}

// PreAlloc

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_allocked_vec_zero_init_is_false() {
    assert!(!<AllockedVec<RedoubtCodecTestBreaker> as PreAlloc>::ZERO_INIT);
}

#[test]
fn test_allocked_vec_prealloc_zeroizes_existing_elements() {
    let mut vec = make_allocked_vec(&[
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 200),
    ]);

    vec.prealloc(2);

    assert_eq!(vec.len(), 2);

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(vec.is_zeroized());
    }

    #[cfg(not(feature = "zeroize"))]
    {
        assert_eq!(vec[0].data, 100);
        assert_eq!(vec[1].data, 200);
    }
}

#[test]
fn test_allocked_vec_prealloc_shrinks() {
    let mut vec = make_allocked_vec(&[
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 1),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 2),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 3),
    ]);
    vec.prealloc(1);

    assert_eq!(vec.len(), 1);
}

#[test]
fn test_allocked_vec_prealloc_grows() {
    let mut vec = make_allocked_vec(&[RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        1,
    )]);
    vec.prealloc(3);

    assert_eq!(vec.len(), 3);
}
