// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memcode_core::{MemBytesRequired, MemDecode, MemEncode, MemEncodeBuf, MemNumElements};

use crate::{ZeroizationProbe, secret::Secret};

#[test]
fn test_secret_mem_num_elements() {
    let bytes = [u8::MAX; 32];
    let secret = Secret::from(bytes);
    assert_eq!(secret.mem_num_elements(), 2);
}

#[test]
fn test_secret_mem_zeroizable() {
    let bytes = [u8::MAX; 32];
    let mut secret = Secret::from(bytes);
    let bytes_required = secret
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    let less_than_bytes_required = bytes_required - 1;
    let mut buf = MemEncodeBuf::new(less_than_bytes_required);

    let result = secret.drain_into(&mut buf);

    assert!(result.is_err());

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
    assert!(secret.is_zeroized());
}

#[test]
fn test_secret_encode_decode_roundtrip() {
    let mut bytes = Vec::<u8>::new();
    bytes.resize_with(32, || u8::MAX);
    let mut secret = Secret::from(bytes);

    // Assert (not) zeroization!
    assert!(!secret.is_zeroized());

    let mut buf: MemEncodeBuf = MemEncodeBuf::new(
        secret
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    secret
        .drain_into(&mut buf)
        .expect("Failed to drain_into(..)");

    // Assert zeroization!
    assert!(secret.is_zeroized());

    let mut recovered_secret = Secret::from(Vec::<u8>::new());

    recovered_secret
        .drain_from(buf.as_mut_slice())
        .expect("Failed to drain_from(..)");

    assert_eq!(recovered_secret.expose().len(), 32);
    assert!(recovered_secret.expose().iter().all(|b| *b == u8::MAX));

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
}
