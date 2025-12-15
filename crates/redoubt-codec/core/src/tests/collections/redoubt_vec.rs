// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::RedoubtVec;
use redoubt_zero::ZeroizationProbe;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

#[test]
fn test_redoubt_vec_codec_roundtrip() {
    let mut vec = RedoubtVec::<u8>::new();
    vec.drain_slice(&mut [1, 2, 3, 4, 5]);

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

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(vec.is_zeroized());
    }
}
