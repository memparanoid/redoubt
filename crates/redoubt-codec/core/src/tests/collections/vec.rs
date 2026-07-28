// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_test_utils::{apply_permutation, index_permutations};
use redoubt_zero::{FastZeroizable, ZeroizationProbe};

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::collections::vec::vec_prealloc;
use crate::error::{DecodeError, EncodeError, OverflowError, RedoubtCodecBufferError};
use crate::support::test_utils::{RedoubtCodecTestBreaker, RedoubtCodecTestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, Encode};

use super::utils::test_collection_varying_capacities;

// Bytes Required
#[test]
fn test_bytes_required_propagates_overflow_error() {
    let vec = vec![
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 10),
        RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
            10,
        ),
    ];

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
    let vec = vec![
        RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
        RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::BytesRequiredReturn(usize::MAX / 2),
            10,
        ),
    ];

    let result = vec.encode_bytes_required();

    assert!(result.is_err());
    assert!(matches!(result, Err(OverflowError { .. })));
}

// Encode

#[test]
fn test_encode_into_propagates_bytes_required_error() {
    let mut vec = vec![RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
        10,
    )];
    let enough_bytes_required = 1024;
    let mut buf = RedoubtCodecBuffer::with_capacity(enough_bytes_required);

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(EncodeError::OverflowError(_))));

    // Assert zeroization!
    assert!(buf.is_zeroized());
    assert!(vec.is_zeroized());
}

#[test]
fn test_encode_propagates_capacity_exceeded_error() {
    let mut vec = vec![RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        100,
    )];
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small

    let result = vec.encode_into(&mut buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EncodeError::RedoubtCodecBufferError(
            RedoubtCodecBufferError::CapacityExceeded
        ))
    ));

    // Assert zeroization!
    assert!(buf.is_zeroized());
    assert!(vec.is_zeroized());
}

// Decode

#[test]
fn test_vec_decode_from_propagates_process_header_err() {
    let mut vec: Vec<RedoubtCodecTestBreaker> = Vec::new();
    let mut buf = RedoubtCodecBuffer::with_capacity(1); // Too small for header

    let mut decode_buf = buf.export_as_vec();
    let result = vec.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));

    // Assert zeroization!
    assert!(buf.is_zeroized());
    assert!(decode_buf.is_zeroized());
    assert!(vec.is_zeroized());
}

#[test]
fn test_vec_decode_propagates_decode_err() {
    let mut vec = vec![
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100),
    ];
    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut recovered = vec![
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceDecodeError, 100),
    ];

    let mut decode_buf = buf.export_as_vec();
    let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::IntentionalDecodeError)));

    // Assert zeroization!
    assert!(buf.is_zeroized());
    assert!(decode_buf.is_zeroized());
    assert!(vec.is_zeroized());
    assert!(recovered.is_zeroized());
}

// Roundtrip

#[test]
fn test_vec_encode_decode_roundtrip() {
    // Encode
    let mut vec = vec![
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 7),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 37),
    ];
    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    {
        let mut decode_buf = buf.export_as_vec();
        let mut recovered = vec![
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 0),
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 0),
        ];
        let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

        assert!(result.is_ok());
        assert_eq!(
            recovered,
            vec![
                RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 7),
                RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 37),
            ]
        );

        // Assert zeroization!
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
    }

    // Assert zeroization!
    assert!(buf.is_zeroized());
    assert!(vec.is_zeroized());
}

// Perm tests

#[test]
fn perm_test_vec_encode_into_propagates_error_at_any_position() {
    let vec = vec![
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            1,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            2,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            3,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            4,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            5,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::ForceEncodeError,
            6,
        )],
    ];
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
        assert!(buf.is_zeroized());
        assert!(vec_clone.is_zeroized());
    });
}

#[test]
fn perm_test_vec_decode_from_propagates_error_at_any_position() {
    let vec = vec![
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            1,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            2,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            3,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            4,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            5,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            6,
        )],
    ];

    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");

    let mut recovered_vec = vec.clone();
    recovered_vec[0][0].set_behaviour(RedoubtCodecTestBreakerBehaviour::ForceDecodeError);

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

            // Assert zeroization!
            assert!(decode_buf.is_zeroized());
            assert!(recovered_vec_clone.is_zeroized());
        }

        // Assert zeroization!
        assert!(buf.is_zeroized());
        assert!(vec_clone.is_zeroized());
    });
}

#[test]
fn perm_test_encode_decode_roundtrip() {
    // Encode
    let vec = vec![
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            1,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            2,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            3,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            4,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            5,
        )],
        vec![RedoubtCodecTestBreaker::new(
            RedoubtCodecTestBreakerBehaviour::None,
            6,
        )],
    ];

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

        // Decode
        {
            let mut recovered: Vec<Vec<RedoubtCodecTestBreaker>> = Vec::new();
            let mut decode_buf = buf.export_as_vec();
            let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

            assert!(result.is_ok());
            assert_eq!(recovered, expected);

            // Assert zeroization!
            assert!(decode_buf.is_zeroized());
        }

        // Assert zeroization!
        assert!(buf.is_zeroized());
        assert!(vec_clone.is_zeroized());
    });
}

// Integration

#[test]
fn test_vec_with_varying_capacities() {
    // `test_collection_varying_capacities` is doubly nested — `for i in 0..len`
    // and, inside it, `for j in 0..i * 2` — so the cost is quadratic in this
    // count, with a clone, an encode, a decode and a zeroization probe on every
    // pass. The other callers take this from `EQUIDISTANT_SAMPLE_SIZE`, which
    // is already gated; this one had it inline, so it needs its own.
    #[cfg(miri)]
    const COUNT: usize = 16;
    #[cfg(not(miri))]
    const COUNT: usize = 250;

    let set: Vec<_> = (0..COUNT)
        .map(|i| RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i))
        .collect();

    test_collection_varying_capacities(
        &set,
        Vec::with_capacity,
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
    let mut vec: Vec<RedoubtCodecTestBreaker> = Vec::new();
    vec_prealloc(&mut vec, 10, true);

    assert_eq!(vec.len(), 10);
    // Fast path memsets to 0
    assert!(vec.is_zeroized());
}

#[test]
fn test_vec_prealloc_zero_init_false() {
    let mut vec: Vec<RedoubtCodecTestBreaker> = Vec::new();
    vec_prealloc(&mut vec, 5, false);

    assert_eq!(vec.len(), 5);
    assert!(vec.is_zeroized());
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_vec_zero_init_is_false() {
    use crate::traits::PreAlloc;
    assert!(!<Vec<RedoubtCodecTestBreaker> as PreAlloc>::ZERO_INIT);
}

#[test]
fn test_vec_prealloc_zeroizes_existing_elements() {
    let mut vec = vec![
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 200),
    ];

    vec_prealloc(&mut vec, 2, false);

    assert_eq!(vec.len(), 2);
    // fast_zeroize() always zeroizes, regardless of zeroize feature
    assert!(vec.is_zeroized());
}

#[test]
fn test_vec_prealloc_zeroizes_large_vec() {
    // Force multiple reallocations with many elements.
    //
    // A `Vec` grows by doubling, so the number of reallocations is logarithmic:
    // 512 elements already means nine of them, and 10,000 means fourteen. The
    // property being tested — that shrinking through `vec_prealloc` zeroizes
    // everything it drops, across several reallocations — is reached at either
    // count. What is not reachable at 10,000 is Miri, which interprets every
    // construction, drop and zeroizing write, so the full count still runs
    // under `cargo test`.
    #[cfg(miri)]
    const COUNT: usize = 512;
    #[cfg(not(miri))]
    const COUNT: usize = 10_000;

    let mut vec: Vec<RedoubtCodecTestBreaker> = (0..COUNT)
        .map(|i| RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i))
        .collect();

    vec_prealloc(&mut vec, COUNT / 2, false);

    assert_eq!(vec.len(), COUNT / 2);
    assert!(vec.is_zeroized(), "Large vec should be fully zeroized");
}

#[test]
fn test_vec_prealloc_shrinks() {
    let mut vec = vec![
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 1),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 2),
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 3),
    ];
    vec_prealloc(&mut vec, 1, false);

    assert_eq!(vec.len(), 1);
}

#[test]
fn test_vec_prealloc_grows() {
    let mut vec = vec![RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::None,
        1,
    )];
    vec_prealloc(&mut vec, 3, false);

    assert_eq!(vec.len(), 3);
}

// Stress tests
#[test]
fn stress_test_vec_clear_push_encode_decode_cycles() {
    // The loop runs SIZE+1 cycles and each one builds a payload of length i,
    // so the work is quadratic: ~500k formatted characters plus an encode and a
    // decode of every intermediate size. Compiled that is a second; interpreted
    // by Miri it does not finish.
    //
    // What the cycle proves — that clear/push/encode/decode round-trips at
    // every length and leaves nothing behind — holds at twenty sizes as well as
    // at a thousand. The full sweep still runs under `cargo test`.
    #[cfg(miri)]
    const SIZE: usize = 20;
    #[cfg(not(miri))]
    const SIZE: usize = 1000;

    let original: Vec<RedoubtCodecTestBreaker> = (0..SIZE)
        .map(|i| RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i))
        .collect();

    let mut vec = Vec::new();

    for i in (0..=SIZE).rev() {
        vec.fast_zeroize();
        vec.clear();
        vec.extend_from_slice(&original[0..i]);

        let bytes_required = vec
            .encode_bytes_required()
            .expect("Failed encode_bytes_required");
        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);
        vec.encode_into(&mut buf).expect("Failed encode_into");

        let mut recovered: Vec<RedoubtCodecTestBreaker> = Vec::new();
        let mut decode_buf = buf.export_as_vec();
        recovered
            .decode_from(&mut decode_buf.as_mut_slice())
            .expect("Failed decode_from");

        assert_eq!(recovered, &original[0..i], "Cycle failed at i={}", i);

        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(vec.is_zeroized());
    }
}
