// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! SHA-256 hash test runners.
//!
//! References:
//! [1] FIPS 180-4: Secure Hash Standard (SHS)
//! [2] RFC 6234: US Secure Hash Algorithms

use crate::HkdfApi;

/// Run SHA-256 hash tests (FIPS 180-4 vectors) against a backend.
pub fn run_sha256_hash_tests(backend: &mut impl HkdfApi) {
    test_sha256_hash_abc(backend);
    test_sha256_hash_empty(backend);
    test_sha256_hash_56_bytes(backend);
    test_sha256_hash_112_bytes(backend);
}

fn test_sha256_hash_abc(backend: &mut impl HkdfApi) {
    let mut digest = [0u8; 32];
    backend.api_sha256_hash(b"abc", &mut digest);

    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
        0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
        0xf2, 0x00, 0x15, 0xad,
    ];

    assert_eq!(digest, expected, "SHA-256 hash mismatch for 'abc'");
}

fn test_sha256_hash_empty(backend: &mut impl HkdfApi) {
    let mut digest = [0u8; 32];
    backend.api_sha256_hash(b"", &mut digest);

    let expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
        0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
        0x78, 0x52, 0xb8, 0x55,
    ];

    assert_eq!(digest, expected, "SHA-256 hash mismatch for empty message");
}

fn test_sha256_hash_56_bytes(backend: &mut impl HkdfApi) {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(msg.len(), 56);

    let mut digest = [0u8; 32];
    backend.api_sha256_hash(msg, &mut digest);

    let expected = [
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
        0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
        0x19, 0xdb, 0x06, 0xc1,
    ];

    assert_eq!(digest, expected, "SHA-256 hash mismatch for 56-byte message");
}

fn test_sha256_hash_112_bytes(backend: &mut impl HkdfApi) {
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(msg.len(), 112);

    let mut digest = [0u8; 32];
    backend.api_sha256_hash(msg, &mut digest);

    let expected = [
        0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04,
        0x92, 0x37, 0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03,
        0x7a, 0xfe, 0xe9, 0xd1,
    ];

    assert_eq!(
        digest, expected,
        "SHA-256 hash mismatch for 112-byte message"
    );
}
