// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::{MemDecodeError, MemEncodeBufError, MemEncodeError};
use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{MemBytesRequired, MemDecode, MemEncode, MemNumElements};

#[test]
fn test_mem_num_elements() {
    macro_rules! run_test_for {
        ($ty:ty) => {{
            let min_value: $ty = 0;
            let max_value = <$ty>::MAX;
            assert_eq!(min_value.mem_num_elements(), 1);
            assert_eq!(max_value.mem_num_elements(), 1);
        }};
    }

    run_test_for!(u8);
    run_test_for!(u16);
    run_test_for!(u32);
    run_test_for!(u64);
}

#[test]
fn test_mem_bytes_required() {
    let u8 = u8::MAX;
    let bytes_required = u8
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    assert_eq!(bytes_required, 1);

    let u16 = u16::MAX;
    let bytes_required = u16
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    assert_eq!(bytes_required, 2);

    let u32 = u32::MAX;
    let bytes_required = u32
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    assert_eq!(bytes_required, 4);

    let u64 = u64::MAX;
    let bytes_required = u64
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    assert_eq!(bytes_required, 8);

    let u128 = u128::MAX;
    let bytes_required = u128
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");
    assert_eq!(bytes_required, 16);
}

#[test]
fn test_encode_decode_roundtrip() {
    macro_rules! run_test_for {
        ($ty:ty) => {{
            let mut max_value = <$ty>::MAX;
            let mut buf = MemEncodeBuf::new(
                max_value
                    .mem_bytes_required()
                    .expect("Failed to calculate mem_encode_header()"),
            );

            max_value
                .drain_into(&mut buf)
                .expect("Failed to drain_into(..)");

            let mut recovered = <$ty>::default();
            recovered
                .drain_from(buf.as_mut_slice())
                .expect("Failed to drain_from(..)");

            assert_eq!(recovered, <$ty>::MAX);

            // Assert zeroization!
            assert_eq!(max_value, 0);
            assert!(buf.as_slice().iter().all(|b| *b == 0));
        }};
    }

    run_test_for!(u8);
    run_test_for!(u16);
    run_test_for!(u32);
    run_test_for!(u64);
}

#[test]
fn test_encode_fails_due_to_mem_encode_buf_insufficient_capacity() {
    macro_rules! run_test_for {
        ($ty:ty) => {{
            let mut max_value = <$ty>::MAX;

            let actual_required_bytes = max_value
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()");
            let less_bytes_tan_required = actual_required_bytes - 1;
            let mut buf = MemEncodeBuf::new(less_bytes_tan_required);

            let result = max_value.drain_into(&mut buf);

            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(MemEncodeError::MemEncodeBufError(
                    MemEncodeBufError::CapacityExceededError
                ))
            ));

            // Assert zeroization!
            assert_eq!(max_value, 0);
            assert!(buf.as_slice().iter().all(|b| *b == 0));
        }};
    }

    run_test_for!(u8);
    run_test_for!(u16);
    run_test_for!(u32);
    run_test_for!(u64);
}

#[test]
fn test_decode_fails_with_insufficient_bytes() {
    macro_rules! run_test_for {
        ($ty:ty) => {{
            let original = <$ty>::MAX;
            let bytes_required = original
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()");

            let mut original_clone = original.clone();
            let mut buf = MemEncodeBuf::new(bytes_required);
            original_clone
                .drain_into(&mut buf)
                .expect("Failed to drain_into(..)");

            let mut tampered_bytes = buf.as_slice()[..bytes_required - 1].to_vec();
            let mut recovered = <$ty>::MAX;
            let result = recovered.drain_from(&mut tampered_bytes);

            assert!(result.is_err());
            assert!(matches!(result, Err(MemDecodeError::LengthMismatch { .. })));

            // Assert zeroization!
            assert_eq!(original_clone, 0);
            assert_eq!(recovered, 0);
            assert!(tampered_bytes.iter().all(|b| *b == 0));
        }};
    }

    run_test_for!(u8);
    run_test_for!(u16);
    run_test_for!(u32);
    run_test_for!(u64);
}

#[test]
fn test_decode_succeeds_with_extra_bytes() {
    macro_rules! run_test_for {
        ($ty:ty) => {{
            let original = <$ty>::MAX;
            let bytes_required = original
                .mem_bytes_required()
                .expect("Failed to get mem_bytes_required()");

            let mut original_clone = original.clone();
            let mut buf = MemEncodeBuf::new(bytes_required);
            original_clone
                .drain_into(&mut buf)
                .expect("Failed to drain_into(..)");

            let mut bytes_with_extra = buf.as_slice().to_vec();
            bytes_with_extra.push(42);
            let extra_byte_idx = bytes_with_extra.len() - 1;

            let mut recovered = 0;
            let consumed = recovered
                .drain_from(&mut bytes_with_extra)
                .expect("Should succeed");

            assert_eq!(consumed, bytes_required);
            assert_eq!(recovered, original);

            // Extra byte should NOT be zeroized (wasn't consumed)
            assert_eq!(bytes_with_extra[extra_byte_idx], 42);

            // Assert zeroization!
            assert!(bytes_with_extra[..consumed].iter().all(|b| *b == 0));
            assert_eq!(original_clone, 0);
        }};
    }

    run_test_for!(u8);
    run_test_for!(u16);
    run_test_for!(u32);
    run_test_for!(u64);
}

#[test]
fn test_zeroizable() {
    macro_rules! run_test_for {
        ($ty:ty) => {{
            use $crate::traits::Zeroizable;

            let mut max_value = <$ty>::MAX;
            max_value.self_zeroize();

            assert_eq!(max_value, 0);
        }};
    }

    run_test_for!(u8);
    run_test_for!(u16);
    run_test_for!(u32);
    run_test_for!(u64);
}
