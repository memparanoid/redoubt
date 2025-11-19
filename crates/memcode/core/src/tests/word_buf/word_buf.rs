// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::{CodecError, WordBufError};
use crate::types::*;
use crate::word_buf::WordBuf;

#[test]
fn word_buf_functional_test() {
    let cap = 512;
    let mut wb = WordBuf::new(cap);

    for i in 0..cap {
        wb.push(i as u32)
            .expect("Failed to push: possible `CapacityExceededError`");
        assert_eq!(wb.remaining(), wb.len() - i - 1);
    }

    let result = wb.push(u32::MAX);

    assert!(result.is_err());
    assert!(matches!(result, Err(WordBufError::CapacityExceededError)));
}

fn run_to_bytes_test_case(len: usize, value: MemCodeWord) {
    let mut expected = Vec::with_capacity(len);
    expected.resize_with(len, || value);

    let mut wb = WordBuf::new(len);
    assert!(wb.as_slice().iter().all(|&b| b == 0));

    for _ in 0..len {
        wb.push(value).expect("Failed to push to buf");
    }

    let mut bytes = wb.to_bytes();

    let mut recovered_wb = WordBuf::new(0);
    let result = recovered_wb.try_from_bytes(&mut bytes);
    assert!(result.is_ok());

    // Assert zeroization (after a successful try_from_bytes)!
    assert!(bytes.iter().all(|&b| b == 0));

    let recovered = recovered_wb.as_slice();

    assert_eq!(recovered, expected);
}

#[test]
fn test_calculate_len_for_bytes() {
    let mut wb = WordBuf::new(1000);

    for i in 0..1000 {
        assert_eq!(wb.calculate_len_for_bytes(), i * 4);
        wb.push(i as MemCodeWord).expect("Failed to push(..)");
    }
}

#[test]
fn test_to_bytes() {
    for i in 0..150 {
        for j in 0..150 {
            run_to_bytes_test_case(i, j);
        }
    }

    for i in 150..300 {
        for j in 150..300 {
            run_to_bytes_test_case(i, j);
        }
    }

    run_to_bytes_test_case(0, u32::MAX);
    run_to_bytes_test_case(256, 0xDEADBEEF);
    run_to_bytes_test_case(1024, 0);
}

#[test]
fn test_try_from_bytes_failure() {
    let len = 512;
    let mut wb = WordBuf::new(len);

    for i in 0..len {
        wb.push(i as MemCodeWord).expect("Failed to push to buf");
    }

    let mut bytes = wb.to_bytes();
    // make bytes.len() % 4 != 0
    bytes.push(len as u8);

    // Assert Zeroization!
    assert!(wb.as_slice().iter().all(|b| *b == 0));

    let mut recovered_wb = WordBuf::new(0);
    let result = recovered_wb.try_from_bytes(&mut bytes);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(WordBufError::CodecError(
            CodecError::InvalidWordStreamLenError { got: 2049 }
        ))
    ));

    // Assert Zeroization!
    assert!(bytes.as_slice().iter().all(|b| *b == 0));
    assert!(recovered_wb.as_slice().iter().all(|b| *b == 0));
}
