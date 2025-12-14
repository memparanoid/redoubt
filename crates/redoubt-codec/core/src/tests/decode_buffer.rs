// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::DecodeBufferError;
use crate::traits::DecodeBuffer;

#[test]
fn test_decode_buffer_reports_out_of_bounds_error() {
    let mut bytes = [0u8; 1];
    let mut dst = 0;
    let result = bytes.as_mut_slice().read_usize(&mut dst);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeBufferError::OutOfBounds)))
}

#[test]
fn test_decode_buffer_read_usize() {
    let values = [1usize, 2, 3, 4, 5, 6];
    let mut bytes = Vec::new();

    // Push each value as native endian bytes
    for &value in &values {
        bytes.extend_from_slice(&value.to_ne_bytes());
    }

    let mut slice = bytes.as_mut_slice();

    // Read back and verify
    for &expected in &values {
        let mut dst = 0;
        slice.read_usize(&mut dst).expect("Failed to read_usize()");
        assert_eq!(dst, expected);
    }
}

#[test]
fn test_decode_buffer_read_slice() {
    let values = [1usize, 2, 3, 4, 5, 6];
    let mut bytes = Vec::new();

    // Push each value as native endian bytes
    for &value in &values {
        bytes.extend_from_slice(&value.to_ne_bytes());
    }

    let mut slice = bytes.as_mut_slice();
    let mut dst = [0usize; 6];

    // Read all values at once
    slice.read_slice(&mut dst).expect("Failed to read_slice()");

    // Verify
    assert_eq!(dst, values);
}
