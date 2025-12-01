// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::utils::test_collection_varying_capacities;
use crate::tests::primitives::utils::{equidistant_unsigned, EQUIDISTANT_SAMPLE_SIZE};

fn test_string_varying_capacities(set: &[u8]) {
    test_collection_varying_capacities(
        set,
        |cap| String::with_capacity(cap),
        |s, slice| {
            s.clear();
            // Convert bytes to valid ASCII chars (mod 128)
            for &b in slice {
                s.push((b % 128) as char);
            }
        },
        |a, b| a == b,
    );
}

#[test]
fn test_string_varying_capacities_u8() {
    let set = equidistant_unsigned::<u8>(EQUIDISTANT_SAMPLE_SIZE);
    test_string_varying_capacities(&set);
}
