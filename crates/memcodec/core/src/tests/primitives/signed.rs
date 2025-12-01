// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::utils::{equidistant_signed, test_all_pairs, EQUIDISTANT_SAMPLE_SIZE};

#[test]
fn test_i8_all_pairs() {
    let set = equidistant_signed::<i8>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_i16_all_pairs() {
    let set = equidistant_signed::<i16>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_i32_all_pairs() {
    let set = equidistant_signed::<i32>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}

#[test]
fn test_i64_all_pairs() {
    let set = equidistant_signed::<i64>(EQUIDISTANT_SAMPLE_SIZE);
    test_all_pairs(&set);
}
