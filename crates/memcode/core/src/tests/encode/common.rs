// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::encode::common::{
    coerce_len_into_mem_code_word, slice_drain_into, slice_drain_into_with,
    slice_drain_into_with_zeroization, slice_required_capacity,
};
use crate::error::{CoerceError, MemEncodeError, WordBufError};
use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

#[test]
fn test_slice_required_capacity_counts_header() {
    let a = [MemCodeUnit::default_zero_value(); 1];
    let b = [MemCodeUnit::default_zero_value(); 2];
    let c = [MemCodeUnit::default_zero_value(); 4];
    let d = [MemCodeUnit::default_zero_value(); 8];
    let e = [MemCodeUnit::default_zero_value(); 16];
    let f = [MemCodeUnit::default_zero_value(); 32];
    let z = [MemCodeUnit::default_zero_value(); 0];

    assert_eq!(slice_required_capacity(&a), 2);
    assert_eq!(slice_required_capacity(&b), 3);
    assert_eq!(slice_required_capacity(&c), 5);
    assert_eq!(slice_required_capacity(&d), 9);
    assert_eq!(slice_required_capacity(&e), 17);
    assert_eq!(slice_required_capacity(&f), 33);
    assert_eq!(slice_required_capacity(&z), 1);
}

#[test]
fn test_len_to_memword_ok_zeroizes_len() {
    let mut us = MemCodeWord::MAX as usize;
    let result = coerce_len_into_mem_code_word(&mut us);

    assert!(result.is_ok());
    assert!(matches!(result, Ok(MemCodeWord::MAX)));

    // Assert zeroization!
    assert_eq!(us, 0);
}

#[test]
fn test_len_to_memword_err_coercion_zeroizes_len() {
    let mut too_big = usize::MAX;
    let result = coerce_len_into_mem_code_word(&mut too_big);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeError::CoerceError(CoerceError::OutOfRange { .. }))
    ));

    // Assert zeroization!
    assert_eq!(too_big, 0);
}

#[test]
fn test_slice_encode_with_err_len_coercion_no_writes() {
    let mut src = [MemCodeUnit::MAX as usize; 64];

    fn f(_: &mut usize) -> Result<MemCodeWord, MemEncodeError> {
        Err(MemEncodeError::CoerceError(CoerceError::OutOfRange {
            value: 0,
            min: 0,
            max: 0,
            src: "a",
            dst: "b",
        }))
    }

    let mut wb = WordBuf::new(500);
    let result = slice_drain_into_with::<usize>(&mut src, &mut wb, &mut f);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemEncodeError::CoerceError(_))));
}

#[test]
fn test_slice_drain_into_with_fails_pushing_len_word() {
    let mut src = [MemCodeUnit::MAX as usize; 64];

    let mut buf = WordBuf::new(0);
    let result =
        slice_drain_into_with::<usize>(&mut src, &mut buf, &mut coerce_len_into_mem_code_word);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeError::WordBufError(
            WordBufError::CapacityExceededError
        ))
    ));
}

#[test]
fn test_slice_drain_into_with_fails_coercing_src_values() {
    let mut src = [usize::MAX; 64];

    let mut buf = WordBuf::new(65);
    let result =
        slice_drain_into_with::<usize>(&mut src, &mut buf, &mut coerce_len_into_mem_code_word);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeError::CoerceError(CoerceError::OutOfRange { .. }))
    ));
}

#[test]
fn test_slice_drain_into_with_fails_pushing_code_units() {
    let mut src = [MemCodeUnit::MAX as usize; 64];

    let mut buf = WordBuf::new(3);
    let result =
        slice_drain_into_with::<usize>(&mut src, &mut buf, &mut coerce_len_into_mem_code_word);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemEncodeError::WordBufError(
            WordBufError::CapacityExceededError
        ))
    ));
}

#[test]
fn test_slice_drain_into_with_lengthy_arrays() {
    let mut src = [MemCodeUnit::MAX as usize; (MemCodeUnit::MAX as usize) * 5];

    let mut buf = WordBuf::new((MemCodeUnit::MAX as usize) * 5 + 1);
    let result =
        slice_drain_into_with::<usize>(&mut src, &mut buf, &mut coerce_len_into_mem_code_word);

    let mut expected = [MemCodeUnit::MAX as MemCodeWord; (MemCodeUnit::MAX as usize) * 5 + 1];
    expected[0] = ((MemCodeUnit::MAX as usize) * 5) as MemCodeWord;

    assert!(result.is_ok());
    assert_eq!(buf.as_slice(), expected);
}

#[test]
fn test_slice_drain_into_with_ok() {
    let mut src = [MemCodeUnit::MAX as usize; 64];

    let mut wb = WordBuf::new(65);
    let result =
        slice_drain_into_with::<usize>(&mut src, &mut wb, &mut coerce_len_into_mem_code_word);

    let mut expected = [MemCodeUnit::MAX as MemCodeWord; 65];
    expected[0] = 64;

    assert!(result.is_ok());
    assert_eq!(wb.as_slice(), expected);

    // Assert zeroization!
    assert!(src.iter().all(|&b| b == 0));
}

#[test]
fn test_slice_encode_with_zeroization_ok_zeroizes_src() {
    let mut src = [MemCodeUnit::MAX as usize; 64];

    let mut buf = WordBuf::new(65);
    let result = slice_drain_into_with_zeroization::<usize>(
        &mut src,
        &mut buf,
        &mut coerce_len_into_mem_code_word,
    );

    assert!(result.is_ok());

    // Assert zeroization!
    assert!(src.iter().all(|&b| b == 0));
}

#[test]
fn test_slice_encode_with_zeroization_err_zeroizes_src_and_buf() {
    let mut src = [MemCodeUnit::MAX as usize; 64];

    fn f(_: &mut usize) -> Result<MemCodeWord, MemEncodeError> {
        Err(MemEncodeError::CoerceError(CoerceError::OutOfRange {
            value: 0,
            min: 0,
            max: 0,
            src: "a",
            dst: "b",
        }))
    }

    let mut wb = WordBuf::new(65);
    let result = slice_drain_into_with_zeroization::<usize>(&mut src, &mut wb, &mut f);

    assert!(result.is_err());

    // Assert zeroization!
    assert!(src.iter().all(|&b| b == 0));
    assert!(wb.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn test_slice_encode_ok_zeroizes_src() {
    let mut src = [MemCodeUnit::MAX as usize; 64];

    let mut buf = WordBuf::new(65);
    let result = slice_drain_into::<usize>(&mut src, &mut buf);

    assert!(result.is_ok());

    // Assert zeroization!
    assert!(src.iter().all(|&b| b == 0));
}
