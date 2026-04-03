// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Shared Wycheproof test runners and FIPS vectors for HKDF-SHA256 backends.
//!
//! This crate provides generic test runners that accept any `HkdfApi`
//! implementation, enabling conformance testing across Rust, x86, and ARM
//! backends without duplicating test code.
//!
//! ## License
//!
//! GPL-3.0-only

#![warn(missing_docs)]

/// HKDF-SHA256 Wycheproof test runner and types.
pub mod hkdf_sha256_wycheproof;
/// HKDF-SHA256 Wycheproof test vectors (auto-generated).
pub mod hkdf_sha256_wycheproof_vectors;
/// HMAC-SHA256 Wycheproof test runner and types.
pub mod hmac_sha256_wycheproof;
/// HMAC-SHA256 Wycheproof test vectors (auto-generated).
pub mod hmac_sha256_wycheproof_vectors;
/// SHA-256 compress_block test runner.
pub mod sha256_compress_block;
/// SHA-256 hash test runner.
pub mod sha256_hash;
