// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;
use memzer::ZeroizationProbe;

use crate::master_key::buffer::{create_buffer, create_initialized_buffer, MASTER_KEY_LEN};

#[test]
fn test_create_buffer_returns_correct_length() {
    let mut buffer = create_buffer(false);
    buffer
        .open(&mut |bytes| {
            assert_eq!(bytes.len(), MASTER_KEY_LEN);
            Ok(())
        })
        .expect("Failed to open buffer");
}

#[test]
fn test_create_buffer_guarded_returns_correct_length() {
    let mut buffer = create_buffer(true);
    buffer
        .open(&mut |bytes| {
            assert_eq!(bytes.len(), MASTER_KEY_LEN);
            Ok(())
        })
        .expect("Failed to open buffer");
}

#[test]
fn test_create_initialized_buffer_returns_correct_length() {
    let buffer = create_initialized_buffer();
    buffer
        .open(&mut |bytes| {
            assert_eq!(bytes.len(), MASTER_KEY_LEN);
            Ok(())
        })
        .expect("Failed to open buffer");
}

#[test]
fn test_create_initialized_buffer_is_not_zero() {
    let buffer = create_initialized_buffer();
    buffer
        .open(&mut |bytes| {
            assert!(!bytes.is_zeroized(), "buffer should be filled with entropy");
            Ok(())
        })
        .expect("Failed to open buffer");
}
