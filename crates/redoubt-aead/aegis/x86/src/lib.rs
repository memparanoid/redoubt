// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! x86_64 assembly AEGIS-128L AEAD implementation.
//!
//! ## License
//!
//! GPL-3.0-only

#![no_std]
#![warn(missing_docs)]

#[cfg(target_arch = "x86_64")]
extern crate alloc;

#[cfg(target_arch = "x86_64")]
use alloc::vec;
#[cfg(target_arch = "x86_64")]
use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use redoubt_aead_core::{AeadApi, AeadError, EntropyError};

/// Key size: 128 bits (16 bytes).
pub const KEY_SIZE: usize = 16;
/// Nonce size: 128 bits (16 bytes).
pub const NONCE_SIZE: usize = 16;
/// Tag size: 128 bits (16 bytes).
pub const TAG_SIZE: usize = 16;

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn aegis128l_encrypt(
        key: *const [u8; 16],
        nonce: *const [u8; 16],
        aad: *const u8,
        aad_len: usize,
        plaintext: *mut u8,
        plaintext_len: usize,
        tag: *mut [u8; 16],
    );

    fn aegis128l_decrypt(
        key: *const [u8; 16],
        nonce: *const [u8; 16],
        aad: *const u8,
        aad_len: usize,
        ciphertext: *mut u8,
        ciphertext_len: usize,
        expected_tag: *const [u8; 16],
        computed_tag: *mut [u8; 16],
    );
}

/// x86_64 assembly AEGIS-128L backend.
pub struct Aegis128LX86Backend;

#[cfg(target_arch = "x86_64")]
impl AeadApi for Aegis128LX86Backend {
    fn api_encrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
        let nonce: &[u8; NONCE_SIZE] = nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
        let tag: &mut [u8; TAG_SIZE] = tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;

        unsafe {
            aegis128l_encrypt(
                key,
                nonce,
                aad.as_ptr(),
                aad.len(),
                data.as_mut_ptr(),
                data.len(),
                tag,
            );
        }

        Ok(())
    }

    fn api_decrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
        let nonce: &[u8; NONCE_SIZE] = nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
        let tag: &[u8; TAG_SIZE] = tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;

        let mut computed_tag = [0u8; TAG_SIZE];

        unsafe {
            aegis128l_decrypt(
                key,
                nonce,
                aad.as_ptr(),
                aad.len(),
                data.as_mut_ptr(),
                data.len(),
                tag,
                &mut computed_tag,
            );
        }

        if redoubt_util::constant_time_eq(&computed_tag, tag) {
            Ok(())
        } else {
            Err(AeadError::AuthenticationFailed)
        }
    }

    fn api_generate_nonce(&mut self) -> Result<Vec<u8>, EntropyError> {
        let mut nonce = vec![0u8; NONCE_SIZE];
        redoubt_rand::fill_with_random_bytes(&mut nonce)?;

        Ok(nonce)
    }

    fn api_key_size(&self) -> usize {
        KEY_SIZE
    }

    fn api_nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn api_tag_size(&self) -> usize {
        TAG_SIZE
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use super::Aegis128LX86Backend;

    #[test]
    fn instrumentation() {
        let _ = super::Aegis128LX86Backend;
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_aegis128l_wycheproof() {
        redoubt_aead_aegis_wycheproof::run_aegis128l_wycheproof_tests(&mut Aegis128LX86Backend);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_aegis128l_roundtrip() {
        redoubt_aead_aegis_wycheproof::run_aegis128l_roundtrip_tests(&mut Aegis128LX86Backend);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_aegis128l_flipped_tag() {
        redoubt_aead_aegis_wycheproof::run_aegis128l_flipped_tag_tests(&mut Aegis128LX86Backend);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_aegis128l_invalid_size_encrypt() {
        redoubt_aead_aegis_wycheproof::run_aegis128l_invalid_size_encrypt_tests(
            &mut Aegis128LX86Backend,
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_aegis128l_invalid_size_decrypt() {
        redoubt_aead_aegis_wycheproof::run_aegis128l_invalid_size_decrypt_tests(
            &mut Aegis128LX86Backend,
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_aegis128l_generate_nonce() {
        redoubt_aead_aegis_wycheproof::run_aegis128l_generate_nonce_test(&mut Aegis128LX86Backend);
    }
}
