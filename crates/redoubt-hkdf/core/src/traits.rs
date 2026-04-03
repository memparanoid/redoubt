// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::HkdfError;

/// Object-safe trait for HKDF-SHA256 backends.
///
/// All methods use the `api_` prefix to avoid collisions with inherent methods
/// on concrete implementations, allowing usage without importing the trait.
///
/// Implemented by:
/// - `RustHkdfBackend` (pure Rust)
/// - `X86HkdfBackend` (x86_64 assembly)
/// - `ArmHkdfBackend` (aarch64 assembly)
pub trait HkdfApi {
    /// HKDF-SHA256 key derivation (RFC 5869).
    fn api_hkdf(
        &mut self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError>;

    /// SHA-256 hash of arbitrary-length data.
    fn api_sha256_hash(&mut self, data: &[u8], out: &mut [u8; 32]);

    /// SHA-256 single-block compression function.
    fn api_sha256_compress_block(&mut self, h: &mut [u32; 8], block: &[u8; 64]);

    /// HMAC-SHA256 (RFC 2104).
    fn api_hmac_sha256(&mut self, key: &[u8], data: &[u8], out: &mut [u8; 32]);
}
