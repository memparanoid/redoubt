// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::MemDecodeError;
use crate::traits::*;
use crate::types::*;

#[test]
fn test_slice_drain_from_err_invariant_violation_zeroizes_words() {
    let mut dst: [MemCodeUnit; 3] = [1, 2, 3];
    let mut words = [4, 1, 2, 3, 4];

    let result = dst.as_mut_slice().drain_from(&mut words);
    assert!(result.is_err());

    // Assert zeroization!
    assert!(words.iter().all(|&b| b == 0));
}

#[test]
fn test_slice_drain_from_err_coerce_zeroizes_words_and_dst() {
    let mut dst = [MemCodeUnit::MAX; 5];
    let mut words = [5, 1, 2, 3, 4, MemCodeWord::MAX];

    assert!(!dst.iter().all(|&b| b == 0));

    let result = dst.as_mut_slice().drain_from(&mut words);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemDecodeError::CoerceError(_))));

    // Assert zeroization!
    assert!(dst.iter().all(|&b| b == 0));
    assert!(words.iter().all(|&b| b == 0));
}

#[test]
fn test_slice_drain_from_large_ok_populates_dst_zeroizes_words() {
    let mut dst = [MemCodeUnit::default_zero_value(); (MemCodeUnit::MAX as usize) * 5];

    let mut words = [MemCodeUnit::MAX as MemCodeWord; (MemCodeUnit::MAX as usize) * 5 + 1];
    words[0] = ((MemCodeUnit::MAX as usize) * 5) as MemCodeWord;

    let expected = [MemCodeUnit::MAX; (MemCodeUnit::MAX as usize) * 5];

    let result = dst.as_mut_slice().drain_from(&mut words);
    assert!(result.is_ok());
    assert_eq!(dst, expected);

    // Assert zeroization!
    assert!(words.iter().all(|&b| b == 0));
}

#[test]
fn test_slice_drain_from_err_zeroizes_dst_and_words() {
    let mut dst = [MemCodeUnit::MAX; (MemCodeUnit::MAX as usize) * 5];

    // invalid pre-condition
    let mut words = [];

    let result = dst.as_mut_slice().drain_from(&mut words);

    assert!(result.is_err());

    // Assert zeroization!
    assert!(words.iter().all(|&b| b == 0));
}

#[test]
fn test_slice_drain_from_ok_populates_dst_zeroizes_words() {
    let mut dst = [MemCodeUnit::default_zero_value(); 5];
    let mut words = [5, 1, 2, 3, 4, 5];

    let result = dst.as_mut_slice().drain_from(&mut words);

    assert!(result.is_ok());
    assert_eq!(dst, [1, 2, 3, 4, 5]);

    // Assert zeroization!
    assert!(words.iter().all(|&b| b == 0));
}
