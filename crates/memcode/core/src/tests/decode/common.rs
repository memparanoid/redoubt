// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::MemCodeUnit;
use crate::decode::common::mem_decode_slice_validate_invariant;
use crate::error::MemDecodeError;

#[test]
fn test_slice_decode_invariant_err_empty_code_and_src() {
    let src: [MemCodeUnit; 0] = [];
    let code = [];
    let result = mem_decode_slice_validate_invariant(src.as_slice(), &code);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
}

#[test]
fn test_slice_decode_invariant_err_header_only_missing_payload() {
    let src: [MemCodeUnit; 0] = [];
    let code = [1];
    let result = mem_decode_slice_validate_invariant(src.as_slice(), &code);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemDecodeError::PreconditionsViolatedError)
    ));
}

#[test]
fn test_slice_decode_invariant_err_length_mismatch_header_exceeds_payload() {
    let src: [MemCodeUnit; 0] = [];
    let code = [2, 1];
    let result = mem_decode_slice_validate_invariant(src.as_slice(), &code);

    assert!(matches!(
        result,
        Err(MemDecodeError::LengthMismatch {
            expected: 2,
            got: 1
        })
    ));
}

#[test]
fn test_slice_decode_invariant_err_length_mismatch_src_len_lt_header() {
    let src: [MemCodeUnit; 3] = [1, 2, 3];
    let code = [4, 1, 2, 3, 4];

    let result = mem_decode_slice_validate_invariant(src.as_slice(), &code);

    assert!(matches!(
        result,
        Err(MemDecodeError::LengthMismatch {
            expected: 4,
            got: 3
        })
    ));
}

#[test]
fn test_slice_decode_invariant_ok_zero_and_nonzero_lengths() {
    let dst_1: [MemCodeUnit; 4] = [1, 2, 3, 4];
    let code_1 = [4, 1, 2, 3, 4];

    let dst_2: [MemCodeUnit; 0] = [];
    let code_2 = [0];

    let result_1 = mem_decode_slice_validate_invariant(dst_1.as_slice(), &code_1);
    let result_2 = mem_decode_slice_validate_invariant(dst_2.as_slice(), &code_2);

    assert!(result_1.is_ok());
    assert!(result_2.is_ok());
}
