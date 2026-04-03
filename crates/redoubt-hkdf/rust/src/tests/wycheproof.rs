// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Wycheproof conformance tests for the pure Rust backend.

use crate::RustBackend;

#[test]
fn test_sha256_hash() {
    redoubt_hkdf_wycheproof::sha256_hash::run_sha256_hash_tests(&mut RustBackend);
}

#[test]
fn test_sha256_compress_block() {
    redoubt_hkdf_wycheproof::sha256_compress_block::run_sha256_compress_block_tests(
        &mut RustBackend,
    );
}

#[test]
fn test_hmac_sha256_wycheproof() {
    redoubt_hkdf_wycheproof::hmac_sha256_wycheproof::run_hmac_wycheproof_tests(&mut RustBackend);
}

#[test]
fn test_hkdf_sha256_wycheproof() {
    redoubt_hkdf_wycheproof::hkdf_sha256_wycheproof::run_hkdf_wycheproof_tests(&mut RustBackend);
}
