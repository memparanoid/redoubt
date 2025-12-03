// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;
#[cfg(feature = "zeroize")]
use memzer::ZeroizationProbe;

use crate::error::{CodecBufferError, DecodeError, EncodeError, OverflowError};
use crate::support::test_utils::{
    TestBreaker, TestBreakerBehaviour, apply_permutation, index_permutations,
};
use crate::traits::{BytesRequired, Decode, Encode, PreAlloc};

// Bytes Required

#[test]
fn test_array_bytes_required_propagates_overflow_error() {
    let arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 10),
        TestBreaker::new(TestBreakerBehaviour::ForceBytesRequiredOverflow, 10),
    ];

    let result = arr.mem_bytes_required();

    assert!(result.is_err());
    match result {
        Err(OverflowError { reason }) => {
            assert_eq!(reason, "TestBreaker forced overflow");
        }
        _ => panic!("Expected OverflowError"),
    }
}

#[test]
fn test_array_bytes_required_reports_overflow_error() {
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
    assert!(matches!(result, Err(OverflowError { .. })));
}

// Encode

#[test]
fn test_array_encode_into_propagates_bytes_required_error() {
    let mut arr = [TestBreaker::new(
        TestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    )];
    let enough_bytes_required = 1024;
    let mut buf = Buffer::new(enough_bytes_required);

    let result = arr.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(EncodeError::OverflowError(_))));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(arr.iter().all(|tb| tb.is_zeroized()));
    }
}

#[test]
fn test_array_encode_propagates_capacity_exceeded_error() {
    let mut arr = [TestBreaker::new(TestBreakerBehaviour::None, 100)];
    let mut buf = Buffer::new(1); // Too small

    let result = arr.encode_into(&mut buf);

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
        assert!(arr.iter().all(|tb| tb.is_zeroized()));
    }
}

// Decode

#[test]
fn test_array_decode_from_propagates_process_header_err() {
    let mut arr: [TestBreaker; 2] = [TestBreaker::default(), TestBreaker::default()];
    let mut buf = [0u8; 1]; // Too small for header

    let result = arr.decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_array_decode_from_propagates_size_mismatch_err() {
    // Encode array of size 2
    let mut arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 100),
    ];
    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    arr.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Try to decode into array of size 1
    let mut arr_wrong_size: [TestBreaker; 1] = [TestBreaker::default()];
    let result = arr_wrong_size.decode_from(&mut buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_array_decode_propagates_decode_err() {
    let mut arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 100),
    ];
    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);

    arr.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut recovered = [
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
        assert!(arr.iter().all(|tb| tb.is_zeroized()));
        assert!(recovered.iter().all(|tb| tb.is_zeroized()));
    }
}

// Roundtrip

#[test]
fn test_array_encode_decode_roundtrip() {
    // Encode
    let mut arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 7),
        TestBreaker::new(TestBreakerBehaviour::None, 37),
    ];
    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);

    arr.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    {
        let mut decode_buf = buf.as_mut_slice();
        let mut recovered = [
            TestBreaker::new(TestBreakerBehaviour::None, 0),
            TestBreaker::new(TestBreakerBehaviour::None, 0),
        ];
        let result = recovered.decode_from(&mut decode_buf);

        assert!(result.is_ok());
        assert_eq!(
            recovered,
            [
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
        assert!(arr.is_zeroized());
    }
}

// Perm tests

#[test]
fn perm_test_array_encode_into_propagates_error_at_any_position() {
    let arr = [
        [TestBreaker::new(TestBreakerBehaviour::None, 1)],
        [TestBreaker::new(TestBreakerBehaviour::None, 2)],
        [TestBreaker::new(TestBreakerBehaviour::None, 3)],
        [TestBreaker::new(TestBreakerBehaviour::None, 4)],
        [TestBreaker::new(TestBreakerBehaviour::None, 5)],
        [TestBreaker::new(TestBreakerBehaviour::ForceEncodeError, 6)],
    ];
    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    index_permutations(arr.len(), |idx_perm| {
        let mut arr_clone = arr;
        apply_permutation(&mut arr_clone, idx_perm);

        let mut buf = Buffer::new(bytes_required);
        let result = arr_clone.encode_into(&mut buf);

        assert!(result.is_err());
        assert!(matches!(result, Err(EncodeError::IntentionalEncodeError)));

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(arr_clone.is_zeroized());
        }
    });
}

#[test]
fn perm_test_array_decode_from_propagates_error_at_any_position() {
    let arr = [
        [TestBreaker::new(TestBreakerBehaviour::None, 1)],
        [TestBreaker::new(TestBreakerBehaviour::None, 2)],
        [TestBreaker::new(TestBreakerBehaviour::None, 3)],
        [TestBreaker::new(TestBreakerBehaviour::None, 4)],
        [TestBreaker::new(TestBreakerBehaviour::None, 5)],
        [TestBreaker::new(TestBreakerBehaviour::None, 6)],
    ];

    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    let mut recovered_arr = arr;
    recovered_arr[0][0].set_behaviour(TestBreakerBehaviour::ForceDecodeError);

    index_permutations(arr.len(), |idx_perm| {
        // Encode
        let mut arr_clone = arr;
        apply_permutation(&mut arr_clone, idx_perm);

        let mut buf = Buffer::new(bytes_required);
        arr_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        {
            let mut recovered_arr_clone = recovered_arr;
            apply_permutation(&mut recovered_arr_clone, idx_perm);

            let mut decode_buf = buf.as_mut_slice();
            let result = recovered_arr_clone.decode_from(&mut decode_buf);

            assert!(result.is_err());
            assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

            #[cfg(feature = "zeroize")]
            // Assert zeroization!
            {
                assert!(decode_buf.is_zeroized());
                assert!(recovered_arr_clone.is_zeroized());
            }
        }

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.as_slice().iter().all(|&b| b == 0));
            assert!(arr_clone.is_zeroized());
        }
    });
}

#[test]
fn perm_test_array_encode_decode_roundtrip() {
    // Encode
    let arr = [
        [TestBreaker::new(TestBreakerBehaviour::None, 1)],
        [TestBreaker::new(TestBreakerBehaviour::None, 2)],
        [TestBreaker::new(TestBreakerBehaviour::None, 3)],
        [TestBreaker::new(TestBreakerBehaviour::None, 4)],
        [TestBreaker::new(TestBreakerBehaviour::None, 5)],
        [TestBreaker::new(TestBreakerBehaviour::None, 6)],
    ];

    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    index_permutations(arr.len(), |idx_perm| {
        let mut arr_clone = arr;
        apply_permutation(&mut arr_clone, idx_perm);

        let expected = arr_clone;

        let mut buf = Buffer::new(bytes_required);
        arr_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        {
            let mut recovered: [[TestBreaker; 1]; 6] = [[TestBreaker::default()]; 6];
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
            assert!(
                arr_clone
                    .iter()
                    .all(|inner| inner.iter().all(|tb| tb.is_zeroized()))
            );
        }
    });
}

// PreAlloc

#[test]
fn test_array_prealloc_is_noop() {
    let mut arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 200),
        TestBreaker::new(TestBreakerBehaviour::None, 300),
    ];
    let arr_clone = arr;

    arr.prealloc(10);

    assert_eq!(arr, arr_clone);
}

// FastZeroizable / FastZeroize

#[cfg(feature = "zeroize")]
#[test]
fn test_array_codec_zeroize_fast_true() {
    use crate::collections::array::array_codec_zeroize;

    // NOTE: fast=true forces memset of entire array, regardless of T::CAN_BE_BULK_ZEROIZED.
    // This is only safe for types where all-zeros is a valid bit pattern.
    // TestBreaker happens to be safe (all fields are primitives/Copy), but this
    // test may break if TestBreaker's layout changes.
    let mut arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 200),
    ];
    array_codec_zeroize(&mut arr, true);

    // Assert zeroization!
    assert!(arr.iter().all(|tb| tb.is_zeroized()));
}

#[cfg(feature = "zeroize")]
#[test]
fn test_array_codec_zeroize_fast_false() {
    use crate::collections::array::array_codec_zeroize;

    let mut arr = [
        TestBreaker::new(TestBreakerBehaviour::None, 100),
        TestBreaker::new(TestBreakerBehaviour::None, 200),
    ];
    array_codec_zeroize(&mut arr, false);

    // Assert zeroization!
    assert!(arr.iter().all(|tb| tb.is_zeroized()));
}
