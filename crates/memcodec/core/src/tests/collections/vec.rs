// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use mem_test_utils::{apply_permutation, index_permutations};
use memzer::ZeroizationProbe;

use crate::codec_buffer::CodecBuffer;
use crate::error::{CodecBufferError, DecodeError, EncodeError, OverflowError};
use crate::support::test_utils::{TestBreaker, TestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, Encode};

use super::utils::test_collection_varying_capacities;

// Bytes Required
#[test]
fn test_bytes_required_propagates_overflow_error() {
    let vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 10),
        TestBreaker::new(TestBreakerBehaviour::ForceBytesRequiredOverflow, 10),
    ];

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
    let vec = vec![
        TestBreaker::new(
            TestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
        TestBreaker::new(
            TestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
    ];

    let result = vec.mem_bytes_required();

    assert!(result.is_err());
    assert!(matches!(result, Err(OverflowError { .. })));
}

// Encode

#[test]
fn test_encode_into_propagates_bytes_required_error() {
    let mut vec = vec![TestBreaker::new(
        TestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    )];
    let enough_bytes_required = 1024;
    let mut buf = CodecBuffer::new(enough_bytes_required);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(EncodeError::OverflowError(_))));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(vec.iter().all(|tb| tb.is_zeroized()));
    }
}

#[test]
fn test_encode_propagates_capacity_exceeded_error() {
    let mut vec = vec![TestBreaker::new(TestBreakerBehaviour::None, 100)];
    let mut buf = CodecBuffer::new(1); // Too small

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
        assert!(vec.iter().all(|tb| tb.is_zeroized()));
    }
}

// Decode

#[test]
fn test_vec_decode_from_propagates_process_header_err() {
    let mut vec: Vec<TestBreaker> = Vec::new();
    let mut buf = [0u8; 1]; // Too small for header

    let result = vec.decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_vec_decode_propagates_decode_err() {
    let mut vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 100),
    ];
    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut recovered = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::ForceDecodeError, 100),
    ];

    let mut decode_buf = buf.as_mut_slice();
    let result = recovered.decode_from(&mut decode_buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(decode_buf.is_zeroized());
        assert!(vec.iter().all(|tb| tb.is_zeroized()));
        assert!(recovered.iter().all(|tb| tb.is_zeroized()));
    }
}

// Roundtrip

#[test]
fn test_vec_encode_decode_roundtrip() {
    // Encode
    let mut vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 7),
        TestBreaker::new(TestBreakerBehaviour::None, 37),
    ];
    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    {
        let mut decode_buf = buf.as_mut_slice();
        let mut recovered = vec![
            TestBreaker::new(TestBreakerBehaviour::None, 0),
            TestBreaker::new(TestBreakerBehaviour::None, 0),
        ];
        let result = recovered.decode_from(&mut decode_buf);

        assert!(result.is_ok());
        assert_eq!(
            recovered,
            vec![
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
        assert!(vec.is_zeroized());
    }
}

// Perm tests

#[test]
fn perm_test_vec_encode_into_propagates_error_at_any_position() {
    let vec = vec![
        vec![TestBreaker::new(TestBreakerBehaviour::None, 1)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 2)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 3)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 4)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 5)],
        vec![TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 6)],
    ];
    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    index_permutations(vec.len(), |idx_perm| {
        let mut vec_clone = vec.clone();
        apply_permutation(vec_clone.as_mut_slice(), idx_perm);

        let mut buf = CodecBuffer::new(bytes_required);
        let result = vec_clone.encode_into(&mut buf);

        assert!(result.is_err());
        assert!(matches!(result, Err(EncodeError::IntentionalEncodeError)));

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(vec_clone.is_zeroized());
        }
    });
}

#[test]
fn perm_test_vec_decode_from_propagates_error_at_any_position() {
    let vec = vec![
        vec![TestBreaker::new(TestBreakerBehaviour::None, 1)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 2)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 3)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 4)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 5)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 6)],
    ];

    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    let mut recovered_vec = vec.clone();
    recovered_vec[0][0].set_behaviour(TestBreakerBehaviour::ForceDecodeError);

    index_permutations(vec.len(), |idx_perm| {
        // Encode
        let mut vec_clone = vec.clone();
        apply_permutation(vec_clone.as_mut_slice(), idx_perm);

        let mut buf = CodecBuffer::new(bytes_required);
        vec_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        {
            let mut recovered_vec_clone = recovered_vec.clone();
            apply_permutation(recovered_vec_clone.as_mut_slice(), idx_perm);

            let mut decode_buf = buf.as_mut_slice();
            let result = recovered_vec_clone.decode_from(&mut decode_buf);

            assert!(result.is_err());
            assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

            #[cfg(feature = "zeroize")]
            // Assert zeroization!
            {
                assert!(decode_buf.is_zeroized());
                assert!(
                    recovered_vec_clone
                        .iter()
                        .all(|v| v.iter().all(|tb| tb.is_zeroized()))
                );
            }
        }

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            // @TODO: use buf.is_zeroized() when new crate is finished.
            assert!(buf.as_slice().iter().all(|&b| b == 0));
            assert!(vec_clone.is_zeroized());
        }
    });
}

#[test]
fn perm_test_encode_decode_roundtrip() {
    // Encode
    let vec = vec![
        vec![TestBreaker::new(TestBreakerBehaviour::None, 1)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 2)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 3)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 4)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 5)],
        vec![TestBreaker::new(TestBreakerBehaviour::None, 6)],
    ];

    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    index_permutations(vec.len(), |idx_perm| {
        let mut vec_clone = vec.clone();
        apply_permutation(vec_clone.as_mut_slice(), idx_perm);

        let expected = vec_clone.clone();

        let mut buf = CodecBuffer::new(bytes_required);
        vec_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        {
            let mut recovered: Vec<Vec<TestBreaker>> = Vec::new();
            let mut decode_buf = buf.as_mut_slice();
            let result = recovered.decode_from(&mut decode_buf);

            assert!(result.is_ok());
            assert_eq!(recovered, expected);

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
            assert!(vec_clone.is_zeroized());
        }
    });
}

// Integration

#[test]
fn test_vec_with_varying_capacities() {
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

// PreAlloc

#[test]
fn test_vec_prealloc_zero_init_true() {
    use crate::collections::vec::vec_prealloc;

    let mut vec: Vec<TestBreaker> = Vec::new();
    vec_prealloc(&mut vec, 10, true);

    assert_eq!(vec.len(), 10);
    // Fast path memsets to 0
    assert!(vec.iter().all(|tb| tb.is_zeroized()));
}

#[test]
fn test_vec_prealloc_zero_init_false() {
    use crate::collections::vec::vec_prealloc;

    let mut vec: Vec<TestBreaker> = Vec::new();
    vec_prealloc(&mut vec, 5, false);

    assert_eq!(vec.len(), 5);
    assert!(vec.iter().all(|tb| tb.usize.data == 104729)); // Default value
}

#[test]
fn test_vec_zero_init_is_false() {
    use crate::traits::PreAlloc;
    assert!(!<Vec<TestBreaker> as PreAlloc>::ZERO_INIT);
}

#[test]
fn test_vec_prealloc_zeroizes_existing_elements() {
    use crate::collections::vec::vec_prealloc;

    let mut vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 200),
    ];

    vec_prealloc(&mut vec, 2, false);

    assert_eq!(vec.len(), 2);
    // fast_zeroize() always zeroizes, regardless of zeroize feature
    assert!(vec.iter().all(|tb| tb.is_zeroized()));
}

#[test]
fn test_vec_prealloc_shrinks() {
    use crate::collections::vec::vec_prealloc;

    let mut vec = vec![
        TestBreaker::new(TestBreakerBehaviour::None, 1),
        TestBreaker::new(TestBreakerBehaviour::None, 2),
        TestBreaker::new(TestBreakerBehaviour::None, 3),
    ];
    vec_prealloc(&mut vec, 1, false);

    assert_eq!(vec.len(), 1);
}

#[test]
fn test_vec_prealloc_grows() {
    use crate::collections::vec::vec_prealloc;

    let mut vec = vec![TestBreaker::new(TestBreakerBehaviour::None, 1)];
    vec_prealloc(&mut vec, 3, false);

    assert_eq!(vec.len(), 3);
}
