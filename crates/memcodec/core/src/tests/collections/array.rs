// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::codec_buffer::CodecBuffer;
use mem_test_utils::{apply_permutation, index_permutations};
#[cfg(feature = "zeroize")]
use memzer::ZeroizationProbe;

use crate::error::{CodecBufferError, DecodeError, EncodeError, OverflowError};
use crate::support::test_utils::{CodecTestBreaker, CodecTestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, Encode, PreAlloc};

// Bytes Required

#[test]
fn test_array_bytes_required_propagates_overflow_error() {
    let arr = [
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 10),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceBytesRequiredOverflow, 10),
    ];

    let result = arr.mem_bytes_required();

    assert!(result.is_err());
    match result {
        Err(OverflowError { reason }) => {
            assert_eq!(reason, "CodecTestBreaker forced overflow");
        }
        _ => panic!("Expected OverflowError"),
    }
}

#[test]
fn test_array_bytes_required_reports_overflow_error() {
    // Two elements each returning usize::MAX / 2 will overflow on the second iteration
    let arr = [
        CodecTestBreaker::new(
            CodecTestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
        CodecTestBreaker::new(
            CodecTestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
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
    let mut arr = [CodecTestBreaker::new(
        CodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    )];
    let enough_bytes_required = 1024;
    let mut buf = CodecBuffer::new(enough_bytes_required);

    let result = arr.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(EncodeError::OverflowError(_))));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(arr.is_zeroized());
    }
}

#[test]
fn test_array_encode_into_propagates_capacity_exceeded_error() {
    let mut arr = [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100)];
    let mut buf = CodecBuffer::new(1); // Too small

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
        assert!(arr.is_zeroized());
    }
}

// Decode

#[test]
fn test_array_decode_from_propagates_process_header_err() {
    let mut arr: [CodecTestBreaker; 2] = [CodecTestBreaker::default(), CodecTestBreaker::default()];
    let mut buf = CodecBuffer::new(1); // Too small for header

    let mut decode_buf = buf.export_as_vec();
    let result = arr.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(arr.is_zeroized());
    }
}

#[test]
fn test_array_decode_from_propagates_size_mismatch_err() {
    // Encode array of size 2
    let mut arr = [
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100),
    ];
    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);
    arr.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Try to decode into array of size 1
    let mut decode_buf = buf.export_as_vec();
    let mut arr_wrong_size: [CodecTestBreaker; 1] = [CodecTestBreaker::default()];
    let result = arr_wrong_size.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(arr.is_zeroized());
        assert!(arr_wrong_size.is_zeroized());
    }
}

#[test]
fn test_array_decode_propagates_decode_err() {
    let mut arr = [
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100),
    ];
    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);

    arr.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut recovered = [
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceDecodeError, 100),
    ];

    let mut decode_buf = buf.export_as_vec();
    let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(arr.is_zeroized());
        assert!(recovered.is_zeroized());
    }
}

// Roundtrip

#[test]
fn test_array_encode_decode_roundtrip() {
    // Encode
    let mut arr = [
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 7),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 37),
    ];
    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = CodecBuffer::new(bytes_required);

    arr.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    {
        let mut decode_buf = buf.export_as_vec();
        let mut recovered = [
            CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 0),
            CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 0),
        ];
        let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

        assert!(result.is_ok());
        assert_eq!(
            recovered,
            [
                CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 7),
                CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 37),
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
        assert!(arr.is_zeroized());
    }
}

// Perm tests

#[test]
fn perm_test_array_encode_into_propagates_error_at_any_position() {
    let arr = [
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 2)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 3)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 4)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 5)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceEncodeError, 6)],
    ];
    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    index_permutations(arr.len(), |idx_perm| {
        let mut arr_clone = arr;
        apply_permutation(&mut arr_clone, idx_perm);

        let mut buf = CodecBuffer::new(bytes_required);
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
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 2)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 3)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 4)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 5)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 6)],
    ];

    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    let mut recovered_arr = arr;
    recovered_arr[0][0].set_behaviour(CodecTestBreakerBehaviour::ForceDecodeError);

    index_permutations(arr.len(), |idx_perm| {
        // Encode
        let mut arr_clone = arr;
        apply_permutation(&mut arr_clone, idx_perm);

        let mut buf = CodecBuffer::new(bytes_required);
        arr_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        {
            let mut recovered_arr_clone = recovered_arr;
            apply_permutation(&mut recovered_arr_clone, idx_perm);

            let mut decode_buf = buf.export_as_vec();
            let result = recovered_arr_clone.decode_from(&mut decode_buf.as_mut_slice());

            assert!(result.is_err());
            assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

            #[cfg(feature = "zeroize")]
            // Assert zeroization!
            {
                assert!(buf.is_zeroized());
                assert!(decode_buf.is_zeroized());
                assert!(recovered_arr_clone.is_zeroized());
            }
        }

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(arr_clone.is_zeroized());
        }
    });
}

#[test]
fn perm_test_array_encode_decode_roundtrip() {
    // Encode
    let arr = [
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 2)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 3)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 4)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 5)],
        [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 6)],
    ];

    let bytes_required = arr
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    index_permutations(arr.len(), |idx_perm| {
        let mut arr_clone = arr;
        apply_permutation(&mut arr_clone, idx_perm);

        let expected = arr_clone;

        let mut buf = CodecBuffer::new(bytes_required);
        arr_clone
            .encode_into(&mut buf)
            .expect("Failed to encode_into(..)");

        // Decode
        {
            let mut recovered: [[CodecTestBreaker; 1]; 6] = [[CodecTestBreaker::default()]; 6];
            let mut decode_buf = buf.export_as_vec();
            let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

            assert!(result.is_ok());
            assert_eq!(recovered, expected);

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
            assert!(arr_clone.is_zeroized());
        }
    });
}

// PreAlloc

#[test]
fn test_array_prealloc_is_noop() {
    let mut arr = [
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 200),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 300),
    ];
    let arr_clone = arr;

    arr.prealloc(10);

    assert_eq!(arr, arr_clone);
}
