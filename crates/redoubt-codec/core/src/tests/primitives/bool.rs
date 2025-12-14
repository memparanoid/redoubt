// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::{DecodeBufferError, DecodeError};
use crate::traits::Decode;

use super::utils::test_all_pairs;

#[test]
fn test_bool_all_pairs() {
    let set = [true, false];
    test_all_pairs(&set);
}

// decode_from empty buffers

#[test]
fn test_bool_decode_from_empty_buffer() {
    let mut value = false;
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
