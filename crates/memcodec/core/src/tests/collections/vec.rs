// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::collections::helpers::{
    bytes_required_sum, decode_fields, encode_fields, to_bytes_required_dyn_ref, to_decode_dyn_mut,
    to_encode_dyn_mut,
};
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::traits::{BytesRequired, Decode, Encode};

#[derive(Debug, PartialEq, Eq)]
struct TwoVecs {
    a: Vec<u8>,
    b: Vec<u8>,
}

impl BytesRequired for TwoVecs {
    fn mem_bytes_required(&self) -> Result<usize, OverflowError> {
        let collection: [&dyn BytesRequired; 2] = [
            to_bytes_required_dyn_ref(&self.a),
            to_bytes_required_dyn_ref(&self.b),
        ];
        bytes_required_sum(collection.into_iter())
    }
}

impl Encode for TwoVecs {
    fn encode_into(&mut self, buf: &mut Buffer) -> Result<(), EncodeError> {
        let collection: [&mut dyn Encode; 2] = [
            to_encode_dyn_mut(&mut self.a),
            to_encode_dyn_mut(&mut self.b),
        ];
        encode_fields(collection.into_iter(), buf)
    }
}

impl Decode for TwoVecs {
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let collection: [&mut dyn Decode; 2] = [
            to_decode_dyn_mut(&mut self.a),
            to_decode_dyn_mut(&mut self.b),
        ];
        decode_fields(collection.into_iter(), buf)
    }
}

#[test]
fn test_roundtrip_vec_u8() {
    // Original data
    let original: Vec<u8> = (0..=255).collect();

    // Encode
    let mut to_encode = original.clone();
    let bytes_required = to_encode
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    to_encode
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    let mut decoded: Vec<u8> = Vec::new();
    decoded
        .decode_from(&mut buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    // Verify
    assert_eq!(original, decoded);
}

#[test]
fn test_two_vecs_roundtrip() {
    let size = 1024 * 1024; // 1MB each

    // Original data
    let original_a: Vec<u8> = vec![0xAA; size];
    let original_b: Vec<u8> = vec![0xBB; size];

    // Encode
    let mut to_encode = TwoVecs {
        a: original_a.clone(),
        b: original_b.clone(),
    };
    let bytes_required = to_encode
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let mut buf = Buffer::new(bytes_required);
    to_encode
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    // Decode
    let mut decoded = TwoVecs {
        a: Vec::new(),
        b: Vec::new(),
    };
    decoded
        .decode_from(&mut buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    // Verify
    let original = TwoVecs {
        a: original_a,
        b: original_b,
    };
    assert_eq!(original, decoded);
}
