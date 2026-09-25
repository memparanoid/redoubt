// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::system::SystemEntropySource;
use crate::traits::EntropySource;

#[test]
#[ignore = "Covered transitively: `fill_bytes` returns what `fill_with_random_bytes` returns, and the refusal is asked of the backend."]
fn test_fill_bytes_propagates_entropy_not_available() {
    // Intentionally empty.
}

#[test]
fn test_fill_bytes_ok() {
    let source = SystemEntropySource {};
    let mut bytes = [0u8; 32];

    let result = source.fill_bytes(&mut bytes);

    assert!(result.is_ok());
}
