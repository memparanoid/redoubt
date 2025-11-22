// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::MemDecodeError;
use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{CollectionDecode, MemBytesRequired, MemDecode, MemEncode};

#[test]
fn test_slice_encode_decode_roundtrip() {
    let mut array = [u128::MAX; 2048];
    let slice = array.as_mut_slice();

    let bytes_required = slice
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required");
    let mut buf = MemEncodeBuf::new(bytes_required);

    // Assert (not) zeroization!
    assert!(slice.iter().any(|&x| x != 0));

    slice
        .drain_into(&mut buf)
        .expect("Failed to drain_into(..)");

    let mut recovered_slice = [0u128; 2048];

    recovered_slice
        .drain_from(buf.as_mut_slice())
        .expect("Failed to drain_from(..)");

    assert_eq!(recovered_slice, [u128::MAX; 2048]);

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
    assert!(slice.iter().all(|b| *b == 0));
}

#[test]
fn test_slice_prepare_with_num_elements_reports_invariant_violated() {
    let mut array = [u128::MAX; 2048];
    let slice = array.as_mut_slice();

    let result = slice.prepare_with_num_elements(1024);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemDecodeError::InvariantViolated)));
}
