// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::RedoubtString;
use redoubt_zero::ZeroizationProbe;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

#[test]
fn test_redoubt_string_codec_roundtrip() {
    let mut s = RedoubtString::new();
    s.extend_from_mut_string(&mut String::from("REDOUBT"));

    let bytes_required = s
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    s.encode_into(&mut buf).expect("Failed to encode_into(..)");

    let mut decode_buf = buf.export_as_vec();
    let mut recovered = RedoubtString::default();

    recovered
        .decode_from(&mut decode_buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    assert_eq!(recovered.as_str(), "REDOUBT");

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(s.is_zeroized());
    }
}

// Stress Tests

#[test]
fn stress_test_redoubt_string_clear_push_encode_decode_cycles() {
    const SIZE: usize = 1000;

    // Create original string (digits 0-999 concatenated)
    let original: String = (0..SIZE).map(|i| format!("{},", i)).collect();

    let mut redoubt_string = RedoubtString::new();

    for i in (0..=SIZE).rev() {
        redoubt_string.clear();

        // Build expected substring
        let expected: String = (0..i).map(|j| format!("{},", j)).collect();

        // Clone the portion we need (RedoubtString doesn't have clone)
        let mut src = expected.clone();
        redoubt_string.extend_from_mut_string(&mut src);

        let bytes_required = redoubt_string
            .encode_bytes_required()
            .expect("Failed encode_bytes_required");
        let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);
        redoubt_string
            .encode_into(&mut buf)
            .expect("Failed encode_into");

        let mut recovered = RedoubtString::new();
        let mut decode_buf = buf.export_as_vec();
        recovered
            .decode_from(&mut decode_buf.as_mut_slice())
            .expect("Failed decode_from");

        assert_eq!(recovered.as_str(), &expected, "Cycle failed at i={}", i);

        #[cfg(feature = "zeroize")]
        {
            assert!(buf.is_zeroized());
            assert!(decode_buf.is_zeroized());
            assert!(src.is_zeroized());
            assert!(redoubt_string.is_zeroized());
        }
    }
}
