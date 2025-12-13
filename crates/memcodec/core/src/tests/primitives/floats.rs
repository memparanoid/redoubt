// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::{DecodeBufferError, DecodeError};
use crate::traits::Decode;

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

// decode_from empty buffers

#[test]
fn test_f32_decode_from_empty_buffer() {
    let mut value = 0.0f32;
    let mut empty_buf = &mut [][..];
    let result = value.decode_from(&mut empty_buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(DecodeError::DecodeBufferError(
            DecodeBufferError::OutOfBounds
        ))
    ));
}

#[test]
fn test_f64_decode_from_empty_buffer() {
    let mut value = 0.0f64;
    let mut empty_buf = &mut [][..];
    let result = value.decode_from(&mut empty_buf);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(DecodeError::DecodeBufferError(
            DecodeBufferError::OutOfBounds
        ))
    ));
}
