// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::RedoubtVec;
use redoubt_zero::ZeroizationProbe;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::support::test_utils::{RedoubtCodecTestBreaker, RedoubtCodecTestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, Encode};

#[test]
fn test_redoubt_vec_codec_roundtrip() {
    let mut vec = RedoubtVec::<u8>::new();
    vec.extend_from_mut_slice(&mut [1, 2, 3, 4, 5]);

    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut decode_buf = buf.export_as_vec();
    let mut recovered = RedoubtVec::<u8>::default();

    recovered
        .decode_from(&mut decode_buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    assert_eq!(recovered.as_slice(), [1, 2, 3, 4, 5]);

    // Assert zeroization!
    assert!(buf.is_zeroized());
    assert!(decode_buf.is_zeroized());
    assert!(vec.is_zeroized());
}

// Stress Tests

#[test]
fn stress_test_redoubt_vec_clear_push_encode_decode_cycles() {
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

    // Create original array (clonable)
    let original: Vec<RedoubtCodecTestBreaker> = (0..SIZE)
        .map(|i| RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i))
        .collect();

    let mut redoubt_vec = RedoubtVec::<RedoubtCodecTestBreaker>::new();

    for i in (0..=SIZE).rev() {
        redoubt_vec.clear();

        // Clone the portion we need from original (RedoubtVec doesn't have clone)
        let mut vec = original[0..i].to_vec();
        redoubt_vec.extend_from_mut_slice(&mut vec);

        let bytes_required = redoubt_vec
            .encode_bytes_required()
            .expect("Failed encode_bytes_required");
        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);
        redoubt_vec
            .encode_into(&mut buf)
            .expect("Failed encode_into");

        let mut recovered = RedoubtVec::<RedoubtCodecTestBreaker>::new();
        let mut decode_buf = buf.export_as_vec();
        recovered
            .decode_from(&mut decode_buf.as_mut_slice())
            .expect("Failed decode_from");

        assert_eq!(
            recovered.as_slice(),
            &original[0..i],
            "Cycle failed at i={}",
            i
        );

        // Assert zeroization!
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(vec.is_zeroized());
        assert!(redoubt_vec.is_zeroized());
    }
}
