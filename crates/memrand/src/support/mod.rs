// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// Test utilities for mocking entropy sources and nonce generators.
///
///Available only when the `test_utils` feature is enabled or during tests.
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;
