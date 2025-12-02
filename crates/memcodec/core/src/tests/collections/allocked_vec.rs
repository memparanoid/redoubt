// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memalloc::AllockedVec;
use membuffer::Buffer;
use memzer::ZeroizationProbe;

use crate::error::{CodecBufferError, DecodeError, EncodeError, OverflowError};
use crate::support::test_utils::{
    TestBreaker, TestBreakerBehaviour, apply_permutation, index_permutations,
};
use crate::traits::{BytesRequired, Decode, Encode, PreAlloc};

fn make_allocked_vec(items: &[TestBreaker]) -> AllockedVec<TestBreaker> {
    let mut vec = AllockedVec::with_capacity(items.len());
    for item in items {
        vec.push(item.clone()).expect("push");
    }
    vec
}

// Bytes Required

#[test]
fn test_bytes_required_propagates_overflow_error() {
    let vec = make_allocked_vec(&[
        TestBreaker::new(TestBreakerBehaviour::None, 10),
        TestBreaker::new(TestBreakerBehaviour::ForceBytesRequiredOverflow, 10),
    ]);

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
fn test_bytes_required_reports_overflow_error() {
    // Two elements each returning usize::MAX / 2 will overflow on the second iteration
    let vec = make_allocked_vec(&[
        TestBreaker::new(
            TestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
        TestBreaker::new(
            TestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
    ]);

    let result = vec.mem_bytes_required();

    assert!(result.is_err());
    assert!(matches!(result, Err(OverflowError { .. })));
}

// Encode

#[test]
fn test_encode_into_propagates_bytes_required_error() {
    let mut vec = make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    )]);
    let enough_bytes_required = 1024;
    let mut buf = Buffer::new(enough_bytes_required);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(EncodeError::OverflowError(_))));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(vec.as_slice().iter().all(|tb| tb.is_zeroized()));
    }
}

#[test]
fn test_encode_propagates_capacity_exceeded_error() {
    let mut vec = make_allocked_vec(&[TestBreaker::new(TestBreakerBehaviour::None, 100)]);
    let mut buf = Buffer::new(1); // Too small

    let result = vec.encode_into(&mut buf);

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
        assert!(vec.as_slice().iter().all(|tb| tb.is_zeroized()));
    }
}

// Decode

#[test]
fn test_allocked_vec_decode_from_propagates_process_header_err() {
    let mut vec: AllockedVec<TestBreaker> = AllockedVec::new();
    let mut buf = [0u8; 1]; // Too small for header

    let result = vec.decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_allocked_vec_decode_propagates_decode_err() {
    let mut vec = make_allocked_vec(&[
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 100),
    ]);
    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut recovered = make_allocked_vec(&[
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::ForceDecodeError, 100),
    ]);

    let mut decode_buf = buf.as_mut_slice();
    let result = recovered.decode_from(&mut decode_buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(vec.as_slice().iter().all(|tb| tb.is_zeroized()));
        assert!(decode_buf.is_zeroized());
        assert!(recovered.as_slice().iter().all(|tb| tb.is_zeroized()));
    }
}

// Roundtrip

#[test]
fn test_allocked_vec_encode_decode_roundtrip() {
    // Encode
    let mut vec = make_allocked_vec(&[
        TestBreaker::new(TestBreakerBehaviour::None, 7),
        TestBreaker::new(TestBreakerBehaviour::None, 37),
    ]);
    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    {
        let mut decode_buf = buf.as_mut_slice();
        let mut recovered = make_allocked_vec(&[
            TestBreaker::new(TestBreakerBehaviour::None, 0),
            TestBreaker::new(TestBreakerBehaviour::None, 0),
        ]);
        let result = recovered.decode_from(&mut decode_buf);

        assert!(result.is_ok());
        assert_eq!(
            recovered.as_slice(),
            &[
                TestBreaker::new(TestBreakerBehaviour::None, 7),
                TestBreaker::new(TestBreakerBehaviour::None, 37),
            ]
        );

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(decode_buf.is_zeroized());
        }
    }

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.as_slice().iter().all(|&b| b == 0));
        assert!(vec.as_slice().iter().all(|tb| tb.is_zeroized()));
    }
}

// Perm tests

#[test]
fn perm_test_allocked_vec_encode_into_propagates_error_at_any_position() {
    let mut vec = AllockedVec::with_capacity(6);
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        1,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        2,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        3,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        4,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        5,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::ForceEncodeError,
        6,
    )]))
    .expect("Failed to push(..)");

    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    index_permutations(vec.len(), |idx_perm| {
        let mut vec_clone = vec.clone();
        apply_permutation(vec_clone.as_mut_slice(), idx_perm);

        let mut buf = Buffer::new(bytes_required);
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
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        1,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        2,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        3,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        4,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        5,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        6,
    )]))
    .expect("Failed to push(..)");

    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    let recovered_vec = {
        let mut recovered_vec = vec.clone();
        recovered_vec.as_mut_slice()[0].as_mut_slice()[0]
            .set_behaviour(TestBreakerBehaviour::ForceDecodeError);
        recovered_vec
    };

    index_permutations(vec.len(), |idx_perm| {
        let mut vec_clone = vec.clone();

        let mut recovered_vec_clone = recovered_vec.clone();
        apply_permutation(recovered_vec_clone.as_mut_slice(), idx_perm);

        let mut buf = Buffer::new(bytes_required);
        vec_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        let mut decode_vec = buf.as_slice().to_vec();
        let mut decode_buf = decode_vec.as_mut_slice();
        let result = recovered_vec_clone.decode_from(&mut decode_buf);

        assert!(result.is_err());
        assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(decode_buf.is_zeroized());
            // @TODO: use vec_clone.is_zeroized() when new crate is finished.
            assert!(
                vec_clone
                    .as_slice()
                    .iter()
                    .all(|v| v.as_slice().iter().all(|tb| tb.is_zeroized()))
            );
            // @TODO: use recovered_vec_clone.is_zeroized() when new crate is finished.
            assert!(
                recovered_vec_clone
                    .as_slice()
                    .iter()
                    .all(|v| v.as_slice().iter().all(|tb| tb.is_zeroized()))
            );
        }
    });
}

#[test]
fn perm_test_allocked_vec_encode_decode_roundtrip() {
    let mut vec: AllockedVec<AllockedVec<TestBreaker>> = AllockedVec::with_capacity(6);
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        1,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        2,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        3,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        4,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        5,
    )]))
    .expect("Failed to push(..)");
    vec.push(make_allocked_vec(&[TestBreaker::new(
        TestBreakerBehaviour::None,
        6,
    )]))
    .expect("Failed to push(..)");

    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    index_permutations(vec.len(), |idx_perm| {
        let mut vec_clone = vec.clone();
        apply_permutation(vec_clone.as_mut_slice(), idx_perm);

        let expected = vec_clone.clone();

        let mut buf = Buffer::new(bytes_required);
        vec_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        let mut decode_vec = buf.as_slice().to_vec();
        let mut decode_buf = decode_vec.as_mut_slice();

        let mut recovered: AllockedVec<AllockedVec<TestBreaker>> = AllockedVec::new();
        let result = recovered.decode_from(&mut decode_buf);

        assert!(result.is_ok());
        assert_eq!(recovered, expected);

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(decode_buf.is_zeroized());
            // @TODO: use vec_clone.is_zeroized() when new crate is finished.
            assert!(
                vec_clone
                    .as_slice()
                    .iter()
                    .all(|v| v.as_slice().iter().all(|tb| tb.is_zeroized()))
            );
        }
    });
}

// PreAlloc

#[test]
fn test_allocked_vec_zero_init_is_false() {
    assert!(!<AllockedVec<TestBreaker> as PreAlloc>::ZERO_INIT);
}

#[test]
fn test_allocked_vec_prealloc_zeroizes_existing_elements() {
    let mut vec = make_allocked_vec(&[
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 200),
    ]);

    vec.prealloc(2);

    assert_eq!(vec.len(), 2);

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        // @TODO: use vec.is_zeroized() when new crate is finished.
        assert!(vec.iter().all(|tb| tb.is_zeroized()));
    }

    #[cfg(not(feature = "zeroize"))]
    {
        // Without zeroize: codec_zeroize() is no-op, elements unchanged
        assert_eq!(vec[0].data, 100);
        assert_eq!(vec[1].data, 200);
    }
}

#[test]
fn test_allocked_vec_prealloc_shrinks() {
    let mut vec = make_allocked_vec(&[
        TestBreaker::new(TestBreakerBehaviour::None, 1),
        TestBreaker::new(TestBreakerBehaviour::None, 2),
        TestBreaker::new(TestBreakerBehaviour::None, 3),
    ]);
    vec.prealloc(1);

    assert_eq!(vec.len(), 1);
}

#[test]
fn test_allocked_vec_prealloc_grows() {
    let mut vec = make_allocked_vec(&[TestBreaker::new(TestBreakerBehaviour::None, 1)]);
    vec.prealloc(3);

    assert_eq!(vec.len(), 3);
}

// CodecZeroize / FastZeroize

#[test]
fn test_vec_codec_zeroize_fast_true() {
    use crate::collections::allocked_vec::allocked_vec_codec_zeroize;

    let mut vec = make_allocked_vec(&[
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 200),
    ]);
    allocked_vec_codec_zeroize(&mut vec, true);

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(vec.iter().all(|tb| tb.is_zeroized()));
    }
}

#[test]
fn test_vec_codec_zeroize_fast_false() {
    use crate::collections::allocked_vec::allocked_vec_codec_zeroize;

    let mut vec = make_allocked_vec(&[
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 200),
    ]);
    allocked_vec_codec_zeroize(&mut vec, false);

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(vec.iter().all(|tb| tb.is_zeroized()));
    }
}
