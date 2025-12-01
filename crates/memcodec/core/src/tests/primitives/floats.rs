// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::utils::test_all_pairs_with;

#[test]
fn test_f32_all_pairs() {
    let set: Vec<f32> = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        f32::MIN,
        f32::MAX,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
        f32::MIN_POSITIVE,
        core::f32::consts::PI,
        core::f32::consts::E,
    ];

    test_all_pairs_with(&set, |a, b| a.to_bits() == b.to_bits());
}

#[test]
fn test_f64_all_pairs() {
    let set: Vec<f64> = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        f64::MIN,
        f64::MAX,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MIN_POSITIVE,
        core::f64::consts::PI,
        core::f64::consts::E,
    ];

    test_all_pairs_with(&set, |a, b| a.to_bits() == b.to_bits());
}
