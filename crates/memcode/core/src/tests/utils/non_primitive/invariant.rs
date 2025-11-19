// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::MemDecodeError;
use crate::types::MemCodeWord;
use crate::utils::non_primitive::mem_decode_validate_invariant;

#[test]
fn test_fields_invariant_err_empty_words() {
    let words: [MemCodeWord; 0] = [];
    let result = mem_decode_validate_invariant(&words, 0);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
}

#[test]
fn test_fields_invariant_err_total_length_mismatch() {
    // header=3, payload=2 → mismatch (expected 3, got 2)
    let words: [MemCodeWord; 3] = [3, 2, 1];
    let result = mem_decode_validate_invariant(&words, 0);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemDecodeError::LengthMismatch { .. })));
}

#[test]
fn test_fields_invariant_err_header_only_but_fields_requested() {
    // header=0, no payload, but fields_len=1 → missing first field header
    let words: [MemCodeWord; 1] = [0];
    let result = mem_decode_validate_invariant(&words, 1);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
}

#[test]
fn test_fields_invariant_err_fields_len_exceeds_available_headers() {
    // header=2, payload has only one field header (1) then one value.
    // Asking for 3 fields forces the loop to run out of headers.
    // Layout: [total=2, f1len=1, v1]
    let words: [MemCodeWord; 3] = [2, 1, 99];
    let result = mem_decode_validate_invariant(&words, 3);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
}

#[test]
fn test_fields_invariant_ok_zero_fields() {
    // header=4, payload=4 → OK even with fields_len=0
    let words: [MemCodeWord; 5] = [4, 10, 20, 30, 40];
    let result = mem_decode_validate_invariant(&words, 0);

    assert!(result.is_ok());
}

#[test]
fn test_fields_invariant_ok_two_fields() {
    // header=5, fields:
    //   f1: len=2, data=10,20
    //   f2: len=1, data=30
    // Layout: [5, 2, 10, 20, 1, 30]
    let words: [MemCodeWord; 6] = [5, 2, 10, 20, 1, 30];
    let result = mem_decode_validate_invariant(&words, 2);

    assert!(result.is_ok());
}

#[test]
fn test_fields_invariant_ok_fields_len_less_than_actual() {
    // Still OK if caller only expects 1 field; function only checks presence of the first header.
    // Layout: [5, 2, 10, 20, 1, 30]
    let words: [MemCodeWord; 6] = [5, 2, 10, 20, 1, 30];
    let result = mem_decode_validate_invariant(&words, 1);

    assert!(result.is_ok());
}
