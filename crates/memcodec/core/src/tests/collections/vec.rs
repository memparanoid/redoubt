// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use super::utils::test_collection_varying_capacities;
use crate::collections::helpers::{
    bytes_required_sum, decode_fields, encode_fields, to_bytes_required_dyn_ref, to_decode_dyn_mut,
    to_encode_dyn_mut,
};
use crate::error::{DecodeError, EncodeError, OverflowError};
use crate::tests::primitives::utils::{equidistant_signed, equidistant_unsigned};
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

fn test_vec_varying_capacities_generic<T>(set: &[T])
where
    T: Clone + PartialEq + core::fmt::Debug,
    Vec<T>: Encode + Decode + BytesRequired + Clone,
{
    test_collection_varying_capacities(
        set,
        |cap| Vec::with_capacity(cap),
        |vec, slice| {
            vec.clear();
            vec.extend_from_slice(slice);
        },
        |a, b| a == b,
    );
}

#[test]
fn test_vec_u8_varying_capacities() {
    let set = equidistant_unsigned::<u8>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_u16_varying_capacities() {
    let set = equidistant_unsigned::<u16>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_u32_varying_capacities() {
    let set = equidistant_unsigned::<u32>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_u64_varying_capacities() {
    let set = equidistant_unsigned::<u64>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_u128_varying_capacities() {
    let set = equidistant_unsigned::<u128>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_usize_varying_capacities() {
    #[cfg(target_pointer_width = "64")]
    let set: Vec<usize> = equidistant_unsigned::<u64>(250)
        .into_iter()
        .map(|x| x as usize)
        .collect();

    #[cfg(target_pointer_width = "32")]
    let set: Vec<usize> = equidistant_unsigned::<u32>(250)
        .into_iter()
        .map(|x| x as usize)
        .collect();

    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_i8_varying_capacities() {
    let set = equidistant_signed::<i8>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_i16_varying_capacities() {
    let set = equidistant_signed::<i16>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_i32_varying_capacities() {
    let set = equidistant_signed::<i32>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_i64_varying_capacities() {
    let set = equidistant_signed::<i64>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_i128_varying_capacities() {
    let set = equidistant_signed::<i128>(250);
    test_vec_varying_capacities_generic(&set);
}

#[test]
fn test_vec_isize_varying_capacities() {
    #[cfg(target_pointer_width = "64")]
    let set: Vec<isize> = equidistant_signed::<i64>(250)
        .into_iter()
        .map(|x| x as isize)
        .collect();

    #[cfg(target_pointer_width = "32")]
    let set: Vec<isize> = equidistant_signed::<i32>(250)
        .into_iter()
        .map(|x| x as isize)
        .collect();

    test_vec_varying_capacities_generic(&set);
}
