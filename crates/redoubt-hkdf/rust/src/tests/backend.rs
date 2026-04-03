// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_hkdf_core::HkdfApi;

use crate::RustBackend;

#[test]
fn test_hkdf_empty_okm() {
    let mut backend = RustBackend;
    let result = backend.api_hkdf(b"salt", b"ikm", b"info", &mut []);

    assert!(result.is_ok());
}
