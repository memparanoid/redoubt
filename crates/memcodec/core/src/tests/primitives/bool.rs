// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::traits::{BytesRequired, Decode, Encode};

/// Generic roundtrip test for bool
fn roundtrip_generic(original_value: bool, initial_recovered: bool) {
    let mut original = original_value;

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

    assert_eq!(recovered, original_value);
}

/// Tests all 4 combinations: (original, initial_recovered)
/// - true -> true (recovered starts as true)
/// - true -> false (recovered starts as false)
/// - false -> true (recovered starts as true)
/// - false -> false (recovered starts as false)
#[test]
fn test_bool_roundtrip_all_combinations() {
    roundtrip_generic(true, true);
    roundtrip_generic(true, false);
    roundtrip_generic(false, true);
    roundtrip_generic(false, false);
}
