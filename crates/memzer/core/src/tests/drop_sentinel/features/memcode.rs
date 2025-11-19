// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use memcode_core::{
    MemBytesRequired, MemDecode, MemDecodeError, MemEncode, MemEncodeBuf, MemEncodeError,
    MemNumElements,
};

use crate::drop_sentinel::DropSentinel;

#[test]
fn test_drop_sentinel_drain_from_with_valid_bytes() {
    let mut bytes = [1u8];
    let mut drop_sentinel = DropSentinel::default();

    let result = drop_sentinel.drain_from(&mut bytes);

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); // consumed 1 byte

    // Assert zeroization!
    assert!(bytes.iter().all(|b| *b == 0));
    assert!(drop_sentinel.is_dropped());
}

#[test]
fn test_drop_sentinel_drain_from_reports_invariant_violated() {
    let mut drop_sentinel = DropSentinel::default();
    let mut bytes = [];

    let result = drop_sentinel.drain_from(&mut bytes);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemDecodeError::InvariantViolated)));

    // Assert zeroization!
    assert!(drop_sentinel.is_dropped());
}

#[test]
fn test_drop_sentinel_mem_num_elements() {
    let drop_sentinel = DropSentinel::default();
    assert_eq!(drop_sentinel.mem_num_elements(), 1);
}

#[test]
fn test_drop_sentinel_drain_into_propagates_buf_drain_byte_error() {
    let mut drop_sentinel_true = DropSentinel::default();
    drop_sentinel_true.zeroize();

    let mut drop_sentinel_false = DropSentinel::default();

    let mut buf_true: MemEncodeBuf = MemEncodeBuf::new(0);
    let mut buf_false = MemEncodeBuf::new(0);

    let result_true = drop_sentinel_true.drain_into(&mut buf_true);

    assert!(result_true.is_err());
    assert!(matches!(
        result_true,
        Err(MemEncodeError::MemEncodeBufError(_))
    ));

    let result_false = drop_sentinel_false.drain_into(&mut buf_false);

    assert!(result_false.is_err());
    assert!(matches!(
        result_false,
        Err(MemEncodeError::MemEncodeBufError(_))
    ));
}

#[test]
fn test_drop_sentinel_encode_decode_roundtrip() {
    let mut drop_sentinel_true = DropSentinel::default();
    drop_sentinel_true.zeroize();

    let mut drop_sentinel_false = DropSentinel::default();

    assert!(drop_sentinel_true.is_dropped());
    assert!(!drop_sentinel_false.is_dropped());

    let mut buf_true: MemEncodeBuf = MemEncodeBuf::new(
        drop_sentinel_true
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );
    let mut buf_false = MemEncodeBuf::new(
        drop_sentinel_false
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    assert_eq!(buf_true.len(), buf_false.len());

    drop_sentinel_true
        .drain_into(&mut buf_true)
        .expect("Failed to drain_into(..)");
    drop_sentinel_false
        .drain_into(&mut buf_false)
        .expect("Failed to drain_into(..)");

    // Assert zeroization! (both dropped)
    assert!(drop_sentinel_true.is_dropped());
    assert!(drop_sentinel_false.is_dropped());

    // Invert value: set to false (decode has to change value)!
    let mut recovered_drop_sentinel_true = DropSentinel::default();
    // Invert value: set to true (decode has to change value)!
    let mut recovered_drop_sentinel_false = DropSentinel::default();
    recovered_drop_sentinel_false.zeroize();

    assert!(!recovered_drop_sentinel_true.is_dropped());
    assert!(recovered_drop_sentinel_false.is_dropped());

    recovered_drop_sentinel_true
        .drain_from(buf_true.as_mut_slice())
        .expect("Failed to drain_from(..)");
    recovered_drop_sentinel_false
        .drain_from(buf_false.as_mut_slice())
        .expect("Failed to drain_from(..)");

    // Assert zeroization!
    assert!(buf_true.as_slice().iter().all(|b| *b == 0));
    assert!(buf_false.as_slice().iter().all(|b| *b == 0));

    // Final assertion (values should have been inverted)
    assert!(recovered_drop_sentinel_true.is_dropped());
    assert!(!recovered_drop_sentinel_false.is_dropped());
}
