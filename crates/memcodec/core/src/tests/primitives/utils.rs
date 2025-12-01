// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::traits::{BytesRequired, Decode, Encode};

/// Tests encode(original) -> decode into recovered -> assert using custom comparator
pub(crate) fn test_roundtrip_with<T, F>(original_value: T, initial_recovered: T, compare: F)
where
    T: Encode + Decode + BytesRequired + Clone,
    F: Fn(&T, &T) -> bool,
{
    let mut original = original_value.clone();

    let mut buf = Buffer::new(
        original
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    original
        .encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    let mut recovered = initial_recovered;
    recovered
        .decode_from(&mut buf.as_mut_slice())
        .expect("Failed to decode_from(..)");

    assert!(compare(&recovered, &original_value));
}

/// For each pair (T_0, T_1) from the set, runs the 4 combinations with custom comparator
pub(crate) fn test_all_pairs_with<T, F>(set: &[T], compare: F)
where
    T: Encode + Decode + BytesRequired + Clone,
    F: Fn(&T, &T) -> bool,
{
    for i in 0..set.len() {
        for j in i..set.len() {
            let t0 = set[i].clone();
            let t1 = set[j].clone();

            test_roundtrip_with(t0.clone(), t0.clone(), &compare);
            test_roundtrip_with(t0.clone(), t1.clone(), &compare);
            test_roundtrip_with(t1.clone(), t0.clone(), &compare);
            test_roundtrip_with(t1.clone(), t1.clone(), &compare);
        }
    }
}

/// For each pair using PartialEq (convenience wrapper)
pub(crate) fn test_all_pairs<T>(set: &[T])
where
    T: Encode + Decode + BytesRequired + Clone + PartialEq,
{
    test_all_pairs_with(set, |a, b| a == b);
}
