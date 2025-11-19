// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::MemDecodeError;
use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{CollectionDecode, MemBytesRequired, MemDecode, MemEncode};

#[test]
fn test_array_encode_decode_roundtrip() {
    let mut array = [u128::MAX; 2048];

    let bytes_required = array
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required");
    let mut buf = MemEncodeBuf::new(bytes_required);

    // Assert (not) zeroization!
    assert!(array.iter().any(|&x| x != 0));

    array
        .drain_into(&mut buf)
        .expect("Failed to drain_into(..)");

    let mut recovered_array = [0u128; 2048];

    recovered_array
        .drain_from(buf.as_mut_slice())
        .expect("Failed to drain_from(..)");

    assert_eq!(recovered_array, [u128::MAX; 2048]);

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
    assert!(array.iter().all(|b| *b == 0));
}

#[test]
fn test_vec_prepare_with_num_elements_reports_inviarant_violated() {
    let mut array = [u128::MAX; 2048];

    let result = array.prepare_with_num_elements(1024);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemDecodeError::InvariantViolated)));
}
