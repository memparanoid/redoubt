// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for HKDF-SHA512

use crate::consts::HASH_LEN;
use crate::error::HkdfError;
use crate::hkdf::hkdf;

#[test]
fn test_hkdf_basic() {
    let ikm = [0x0bu8; 22];
    let salt = [0x00u8; 13];
    let info = [0xf0u8; 10];

    let mut okm = [0u8; 42];
    hkdf(&ikm, &salt, &info, &mut okm).unwrap();

    // Output should be deterministic
    let mut okm2 = [0u8; 42];
    hkdf(&ikm, &salt, &info, &mut okm2).unwrap();
    assert_eq!(okm, okm2);
}

#[test]
fn test_hkdf_empty_salt() {
    let ikm = [0x0bu8; 22];
    let info = b"context";

    let mut okm = [0u8; 32];
    hkdf(&ikm, &[], info, &mut okm).unwrap();

    // Should not panic with empty salt
    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn test_hkdf_empty_info() {
    let ikm = [0x0bu8; 22];
    let salt = [0x00u8; 64];

    let mut okm = [0u8; 32];
    hkdf(&ikm, &salt, &[], &mut okm).unwrap();

    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn test_hkdf_output_16_bytes() {
    let ikm = b"input key material";
    let salt = b"salt value";
    let info = b"aegis128l";

    let mut okm = [0u8; 16];
    hkdf(ikm, salt, info, &mut okm).unwrap();

    assert_ne!(okm, [0u8; 16]);
}

#[test]
fn test_hkdf_output_32_bytes() {
    let ikm = b"input key material";
    let salt = b"salt value";
    let info = b"xchacha20";

    let mut okm = [0u8; 32];
    hkdf(ikm, salt, info, &mut okm).unwrap();

    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn test_hkdf_output_64_bytes() {
    let ikm = b"input key material";
    let salt = b"salt value";
    let info = b"full hash output";

    let mut okm = [0u8; 64];
    hkdf(ikm, salt, info, &mut okm).unwrap();

    assert_ne!(okm, [0u8; 64]);
}

#[test]
fn test_hkdf_output_max() {
    let ikm = b"ikm";
    let salt = b"salt";
    let info = b"info";

    // Max output: 255 * 64 = 16320 bytes
    let mut okm = [0u8; 255 * HASH_LEN];
    hkdf(ikm, salt, info, &mut okm).unwrap();
}

#[test]
fn test_hkdf_output_too_long() {
    let ikm = b"ikm";
    let salt = b"salt";
    let info = b"info";

    let mut okm = [0u8; 255 * HASH_LEN + 1];
    let result = hkdf(ikm, salt, info, &mut okm);

    assert_eq!(result, Err(HkdfError::OutputTooLong));
}

#[test]
fn test_hkdf_empty_output() {
    let ikm = b"ikm";
    let mut okm = [0u8; 0];
    hkdf(ikm, &[], &[], &mut okm).unwrap();
}

#[test]
fn test_hkdf_different_info_different_output() {
    let ikm = b"same ikm";
    let salt = b"same salt";

    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];

    hkdf(ikm, salt, b"info1", &mut okm1).unwrap();
    hkdf(ikm, salt, b"info2", &mut okm2).unwrap();

    assert_ne!(okm1, okm2);
}

#[test]
fn test_hkdf_different_salt_different_output() {
    let ikm = b"same ikm";
    let info = b"same info";

    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];

    hkdf(ikm, b"salt1", info, &mut okm1).unwrap();
    hkdf(ikm, b"salt2", info, &mut okm2).unwrap();

    assert_ne!(okm1, okm2);
}
