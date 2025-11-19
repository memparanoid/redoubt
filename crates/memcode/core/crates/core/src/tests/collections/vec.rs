// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{CollectionDecode, MemBytesRequired, MemDecode, MemEncode};

#[test]
fn test_vec_encode_decode_roundtrip() {
    let mut vec = Vec::<u128>::new();
    vec.resize_with(2048, || u128::MAX);

    let bytes_required = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required");
    let mut buf = MemEncodeBuf::new(bytes_required);

    // Assert (not) zeroization!
    assert!(vec.iter().any(|&x| x != 0));

    vec.drain_into(&mut buf).expect("Failed to drain_into(..)");

    let mut recovered_vec = Vec::<u128>::new();
    recovered_vec.resize_with(2048, || 0);

    recovered_vec
        .drain_from(buf.as_mut_slice())
        .expect("Failed to drain_from(..)");

    assert_eq!(recovered_vec, [u128::MAX; 2048]);

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
    assert!(vec.iter().all(|b| *b == 0));
}

#[test]
fn test_vec_prepare_with_num_elements_expands_vec() {
    let mut vec = Vec::<u128>::new();

    assert_eq!(vec.len(), 0);

    vec.prepare_with_num_elements(1024)
        .expect("Failed to prepare_with_num_elements(..)");

    assert_eq!(vec.len(), 1024);
}
