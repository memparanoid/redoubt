// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::boxed::Box;

use redoubt_zero::ZeroizationProbe;

use crate::codec_buffer::RedoubtCodecBuffer;
use crate::traits::{BytesRequired, Decode, Encode};

#[test]
fn test_box_codec_roundtrip() {
    let mut boxed = Box::new(42u64);

    let bytes_required = boxed
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    boxed
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut decode_buf = buf.export_as_vec();
    let mut recovered = Box::new(0u64);

    recovered
        .decode_from(&mut decode_buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    assert_eq!(*recovered, 42);

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(boxed.is_zeroized());
    }
}

#[test]
fn test_box_large_array_codec_roundtrip() {
    let mut boxed = Box::new([0xAAu8; 1024]);

    let bytes_required = boxed
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = RedoubtCodecBuffer::with_capacity(bytes_required);

    boxed
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut decode_buf = buf.export_as_vec();
    let mut recovered = Box::new([0u8; 1024]);

    recovered
        .decode_from(&mut decode_buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    assert_eq!(*recovered, [0xAAu8; 1024]);

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(boxed.is_zeroized());
    }
}
