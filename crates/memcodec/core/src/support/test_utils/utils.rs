// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// Tampers with encoded bytes by clearing the buffer.
///
/// Used in tests to simulate corrupted or invalid encoded data.
#[cfg(any(test, feature = "test_utils"))]
pub fn tamper_encoded_bytes_for_tests(bytes: &mut [u8]) {
    bytes.fill(0xFF);
}
