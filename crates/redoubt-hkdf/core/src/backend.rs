// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Pure Rust HKDF-SHA256 backend implementing `HkdfApi`.

use crate::error::HkdfError;
use crate::hkdf::HkdfSha256State;
use crate::hmac::HmacSha256State;
use crate::sha256::Sha256State;
use crate::traits::HkdfApi;

const MAX_OUTPUT_LEN: usize = 255 * 32;

/// Pure Rust HKDF-SHA256 backend.
pub struct RustBackend;

impl HkdfApi for RustBackend {
    fn api_hkdf(
        &mut self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        if okm.len() > MAX_OUTPUT_LEN {
            return Err(HkdfError::OutputTooLong);
        }

        if okm.is_empty() {
            return Ok(());
        }

        let mut state = HkdfSha256State::new();
        state.derive(ikm, salt, info, okm);

        Ok(())
    }

    fn api_sha256_hash(&mut self, data: &[u8], out: &mut [u8; 32]) {
        let mut state = Sha256State::new();
        state.hash(data, out);
    }

    fn api_sha256_compress_block(&mut self, h: &mut [u32; 8], block: &[u8; 64]) {
        let mut state = Sha256State::new();
        state.compress_block(h, block);
    }

    fn api_hmac_sha256(&mut self, key: &[u8], data: &[u8], out: &mut [u8; 32]) {
        let mut state = HmacSha256State::new();
        state.sha256(key, data, out);
    }
}
