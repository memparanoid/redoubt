// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::codec::try_take_words_from_bytes_and_zeroize;
use crate::error::CodecError;

#[test]
fn test_try_take_words_from_bytes_zeroizes_input_on_success() {
    let mut bytes = vec![1, 0, 0, 0, 2, 0, 0, 0];

    let result = try_take_words_from_bytes_and_zeroize(bytes.as_mut_slice());
    assert!(result.is_ok());

    // Assert zeroization!
    assert!(bytes.iter().all(|&b| b == 0));
}

#[test]
fn test_try_take_words_from_bytes_err_len_not_multiple_of_4() {
    let mut buf = vec![0xAA, 0xBB, 0xCC];

    let result = try_take_words_from_bytes_and_zeroize(buf.as_mut_slice());

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CodecError::InvalidWordStreamLenError { got: 3 })
    ));

    // Assert zeroization!
    assert!(buf.iter().all(|b| *b == 0));
}

#[test]
fn test_try_take_words_from_bytes_and_zeroize_zeroizes_on_error() {
    let mut buf = vec![0x11, 0x22, 0x33];

    let result = try_take_words_from_bytes_and_zeroize(buf.as_mut_slice());

    assert!(result.is_err());
    assert!(buf.iter().all(|&b| b == 0));

    // Assert zeroization!
    assert!(buf.iter().all(|b| *b == 0));
}
