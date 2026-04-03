// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! x86_64 assembly HKDF-SHA256 implementation.
//!
//! ## License
//!
//! GPL-3.0-only

#![no_std]
#![warn(missing_docs)]

#[cfg(target_arch = "x86_64")]
use redoubt_hkdf_core::{HkdfApi, HkdfError};

#[cfg(target_arch = "x86_64")]
const MAX_OUTPUT_LEN: usize = 255 * 32;

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn sha256_compress_block(h_ptr: *mut u32, block_ptr: *const u8);
    fn sha256_hash(msg_ptr: *const u8, msg_len: usize, digest_ptr: *mut u8);
    fn hmac_sha256(
        key_ptr: *const u8,
        key_len: usize,
        msg_ptr: *const u8,
        msg_len: usize,
        mac_ptr: *mut u8,
    );
    fn hkdf_sha256(
        salt_ptr: *const u8,
        salt_len: usize,
        ikm_ptr: *const u8,
        ikm_len: usize,
        info_ptr: *const u8,
        info_len: usize,
        okm_ptr: *mut u8,
        okm_len: usize,
    );
}

/// x86_64 assembly HKDF-SHA256 backend.
pub struct X86Backend;

#[cfg(target_arch = "x86_64")]
impl HkdfApi for X86Backend {
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

        unsafe {
            hkdf_sha256(
                salt.as_ptr(),
                salt.len(),
                ikm.as_ptr(),
                ikm.len(),
                info.as_ptr(),
                info.len(),
                okm.as_mut_ptr(),
                okm.len(),
            );
        }

        Ok(())
    }

    fn api_sha256_hash(&mut self, data: &[u8], out: &mut [u8; 32]) {
        unsafe {
            sha256_hash(data.as_ptr(), data.len(), out.as_mut_ptr());
        }
    }

    fn api_sha256_compress_block(&mut self, h: &mut [u32; 8], block: &[u8; 64]) {
        unsafe {
            sha256_compress_block(h.as_mut_ptr(), block.as_ptr());
        }
    }

    fn api_hmac_sha256(&mut self, key: &[u8], data: &[u8], out: &mut [u8; 32]) {
        unsafe {
            hmac_sha256(
                key.as_ptr(),
                key.len(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(test, target_arch = "x86_64"))]
    use super::X86Backend;

    #[test]
    fn instrumentation() {
        assert!(true);
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    #[test]
    fn test_sha256_hash() {
        redoubt_hkdf_wycheproof::sha256_hash::run_sha256_hash_tests(&mut X86Backend);
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    #[test]
    fn test_sha256_compress_block() {
        redoubt_hkdf_wycheproof::sha256_compress_block::run_sha256_compress_block_tests(
            &mut X86Backend,
        );
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    #[test]
    fn test_hmac_sha256_wycheproof() {
        redoubt_hkdf_wycheproof::hmac_sha256_wycheproof::run_hmac_wycheproof_tests(
            &mut X86Backend,
        );
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    #[test]
    fn test_hkdf_sha256_wycheproof() {
        redoubt_hkdf_wycheproof::hkdf_sha256_wycheproof::run_hkdf_wycheproof_tests(
            &mut X86Backend,
        );
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    #[test]
    fn test_hkdf_empty_okm() {
        use redoubt_hkdf_core::HkdfApi;
        let result = X86Backend.api_hkdf(b"salt", b"ikm", b"info", &mut []);
        assert!(result.is_ok());
    }
}
