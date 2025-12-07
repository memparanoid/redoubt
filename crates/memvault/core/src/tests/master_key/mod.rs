// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::master_key::buffer::MASTER_KEY_LEN;
use crate::master_key::storage::portable::open as portable_open;
use crate::master_key::storage::std::open as std_open;

#[test]
fn test_std_open_returns_correct_length() {
    std_open(&mut |bytes| {
        assert_eq!(bytes.len(), MASTER_KEY_LEN);
        Ok(())
    })
    .expect("Failed to open std buffer");
}

#[test]
fn test_std_open_returns_same_bytes_on_subsequent_calls() {
    let mut first_bytes = [0u8; MASTER_KEY_LEN];

    std_open(&mut |bytes| {
        first_bytes.copy_from_slice(bytes);
        Ok(())
    })
    .expect("Failed to open std buffer");

    std_open(&mut |bytes| {
        assert_eq!(bytes, &first_bytes);
        Ok(())
    })
    .expect("Failed to open std buffer");
}

#[test]
fn test_portable_open_returns_correct_length() {
    portable_open(&mut |bytes| {
        assert_eq!(bytes.len(), MASTER_KEY_LEN);
        Ok(())
    })
    .expect("Failed to open portable buffer");
}

#[test]
fn test_portable_open_returns_same_bytes_on_subsequent_calls() {
    let mut first_bytes = [0u8; MASTER_KEY_LEN];

    portable_open(&mut |bytes| {
        first_bytes.copy_from_slice(bytes);
        Ok(())
    })
    .expect("Failed to open portable buffer");

    portable_open(&mut |bytes| {
        assert_eq!(bytes, &first_bytes);
        Ok(())
    })
    .expect("Failed to open portable buffer");
}
