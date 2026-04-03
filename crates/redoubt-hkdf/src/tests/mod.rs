// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Facade happy path tests.

#[test]
fn test_hkdf_happy_path() {
    // RFC 5869 Test Vector 1
    let ikm = [0x0bu8; 22];
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

    let mut okm = [0u8; 42];
    let result = crate::hkdf(&salt, &ikm, &info, &mut okm);

    assert!(result.is_ok());
    assert_ne!(okm, [0u8; 42]);
}

#[test]
fn test_hkdf_empty_okm() {
    let result = crate::hkdf(b"salt", b"ikm", b"info", &mut []);

    assert!(result.is_ok());
}

#[test]
fn test_hkdf_output_too_long() {
    let mut okm = [0u8; 255 * 32 + 1];
    let result = crate::hkdf(b"salt", b"ikm", b"info", &mut okm);

    assert!(result.is_err());
}
