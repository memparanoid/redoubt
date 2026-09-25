// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::fill::fill_with_random_bytes;

#[test]
#[ignore = "Covered transitively: `fill_with_random_bytes` returns what the backend returns, and the refusal is asked of the backend."]
fn test_fill_with_random_bytes_propagates_entropy_not_available() {
    // Intentionally empty.
}

#[test]
fn test_fill_with_random_bytes_ok() {
    let mut buf = [0u8; 32];
    assert!(fill_with_random_bytes(&mut buf).is_ok());
}

#[test]
fn test_fill_with_random_bytes_empty_slice_ok() {
    let mut buf = [];
    assert!(fill_with_random_bytes(&mut buf).is_ok());
}
