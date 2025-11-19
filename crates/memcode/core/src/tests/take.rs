// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::CoerceError;
use crate::take::*;
use crate::types::MemCodeWord;

#[test]
fn test_into_memword_zeroizes_on_ok_and_err() {
    let mut in_usize = usize::MAX;
    let mut in_u64 = u64::MAX;
    let mut in_u32 = u32::MAX;
    let mut in_u16 = u16::MAX;
    let mut in_u8 = u8::MAX;
    let mut bool_true = true;
    let mut bool_false = false;

    let result_usize = try_take_into::<usize, MemCodeWord>(&mut in_usize);
    assert!(result_usize.is_err());
    assert!(matches!(result_usize, Err(CoerceError::OutOfRange { .. })));
    // Assert zeroization!
    assert_eq!(in_usize, 0);

    let result_u64 = try_take_into::<u64, MemCodeWord>(&mut in_u64);
    assert!(result_u64.is_err());
    assert!(matches!(result_u64, Err(CoerceError::OutOfRange { .. })));
    // Assert zeroization!
    assert_eq!(in_u64, 0);

    let result_u32 = try_take_into::<u32, MemCodeWord>(&mut in_u32);
    assert!(result_u32.is_ok());
    assert!(matches!(result_u32, Ok(value) if value == u32::MAX as MemCodeWord));
    // Assert zeroization!
    assert_eq!(in_u32, 0);

    let result_u16 = try_take_into::<u16, MemCodeWord>(&mut in_u16);
    assert!(result_u16.is_ok());
    assert!(matches!(result_u16, Ok(value) if value == u16::MAX as MemCodeWord));
    // Assert zeroization!
    assert_eq!(in_u16, 0);

    let result_u8 = try_take_into::<u8, MemCodeWord>(&mut in_u8);
    assert!(result_u8.is_ok());
    assert!(matches!(result_u8, Ok(value) if value == u8::MAX as MemCodeWord));
    // Assert zeroization!
    assert_eq!(in_u8, 0);

    let result_bool_true = try_take_into::<bool, MemCodeWord>(&mut bool_true);
    assert!(result_bool_true.is_ok());
    assert!(matches!(result_bool_true, Ok(1)));
    // Assert zeroization!
    assert_eq!(bool_true, false);

    let result_bool_false = try_take_into::<bool, MemCodeWord>(&mut bool_false);
    assert!(result_bool_false.is_ok());
    assert!(matches!(result_bool_false, Ok(0)));
    // Assert zeroization!
    assert_eq!(bool_false, false);
}

#[test]
fn test_from_memword_overflow_err_zeroizes_source() {
    let mut word_1: MemCodeWord = MemCodeWord::MAX;
    let mut word_2: MemCodeWord = MemCodeWord::MAX;

    let result_u8 = try_take_into::<MemCodeWord, u8>(&mut word_1);
    assert!(result_u8.is_err());
    assert!(matches!(result_u8, Err(CoerceError::OutOfRange { .. })));
    // Assert zeroization!
    assert_eq!(word_1, 0);

    let result_u16 = try_take_into::<MemCodeWord, u16>(&mut word_2);
    assert!(result_u16.is_err());
    assert!(matches!(result_u16, Err(CoerceError::OutOfRange { .. })));
    // Assert zeroization!
    assert_eq!(word_2, 0);
}

#[test]
fn test_from_memword_ok_zeroizes_source() {
    let mut word_small: MemCodeWord = 200;
    let mut word_mid: MemCodeWord = 0xBEEF;
    let mut word_big = 12_345_678;
    let mut word_super_big: MemCodeWord = 123_456_789;
    let mut word_max: MemCodeWord = MemCodeWord::MAX;

    let result_u8 = try_take_into::<MemCodeWord, u8>(&mut word_small);
    assert!(result_u8.is_ok());
    assert_eq!(result_u8.unwrap(), 200u8);
    assert_eq!(word_small, 0);

    let result_u16 = try_take_into::<MemCodeWord, u16>(&mut word_mid);
    assert!(result_u16.is_ok());
    assert_eq!(result_u16.unwrap(), 0xBEEFu16);
    assert_eq!(word_mid, 0);

    let result_u32 = try_take_into::<MemCodeWord, u32>(&mut word_big);
    assert!(result_u32.is_ok());
    assert_eq!(result_u32.unwrap(), 12_345_678u32);
    assert_eq!(word_big, 0);

    let result_u64 = try_take_into::<MemCodeWord, u64>(&mut word_super_big);
    assert!(result_u64.is_ok());
    assert_eq!(result_u64.unwrap(), 123_456_789u64);
    assert_eq!(word_super_big, 0);

    let result_usize = try_take_into::<MemCodeWord, usize>(&mut word_max);
    assert!(result_usize.is_ok());
    assert_eq!(result_usize.unwrap(), MemCodeWord::MAX as usize);
    assert_eq!(word_max, 0);
}

#[test]
fn test_try_take_slice_and_zeroize_src_on_ok() {
    let mut src: Vec<u16> = vec![1, 2, u16::MAX];
    let mut dst: Vec<MemCodeWord> = vec![0; src.len()];

    let result = try_take_slice_and_zeroize_src(&mut src, &mut dst);

    assert!(result.is_ok());
    assert_eq!(dst, vec![1u32, 2u32, u16::MAX as u32]);

    // Assert zeroization!
    assert!(src.iter().all(|b| *b == 0));
}

#[test]
fn test_try_take_slice_and_zeroize_src_ok_failure() {
    let mut src: Vec<u64> = vec![1, 2, (MemCodeWord::MAX as u64) + 1];
    let mut dst: Vec<MemCodeWord> = vec![0; src.len()];

    let result = try_take_slice_and_zeroize_src(&mut src, &mut dst);

    assert!(result.is_err());
    assert!(matches!(result, Err(CoerceError::OutOfRange { .. })));

    // Assert zeroization!
    assert!(src.iter().all(|b| *b == 0));
    assert!(dst.iter().all(|b| *b == 0));
}

#[test]
fn test_try_take_slice_and_zeroize_src_reports_length_mismatch() {
    let mut src: Vec<u64> = vec![1, 2, (MemCodeWord::MAX as u64) + 1];
    let mut dst: Vec<MemCodeWord> = vec![];

    let result = try_take_slice_and_zeroize_src(&mut src, &mut dst);

    assert!(result.is_err());
    assert!(matches!(result, Err(CoerceError::LengthMismatchError)));

    // Assert zeroization!
    assert!(src.iter().all(|b| *b == 0));
    assert!(dst.iter().all(|b| *b == 0));
}
