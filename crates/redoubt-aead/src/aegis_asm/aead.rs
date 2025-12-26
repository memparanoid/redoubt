// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_rand::{
    EntropyError, EntropySource, NonceGenerator, NonceSessionGenerator, SystemEntropySource,
};

use crate::error::AeadError;
use crate::traits::AeadBackend;

use super::consts::{Aegis128LKey, Aegis128LNonce, Aegis128LTag, NONCE_SIZE, KEY_SIZE, TAG_SIZE};

unsafe extern "C" {
    /// Performs one AEGIS-128L state update round with message absorption.
    ///
    /// NOTE: Not used by encrypt/decrypt (they inline updates), but kept for:
    /// - RFC test vector validation (early issue detection)
    /// - Debugging/testing individual update operations
    ///
    /// # Safety
    /// - `state` must point to 128 bytes (8 blocks of 16 bytes each) and be 16-byte aligned
    /// - `m0` must point to 16 bytes (first message block)
    /// - `m1` must point to 16 bytes (second message block)
    #[cfg(all(test, feature = "asm", is_aegis_asm_eligible))]
    pub unsafe fn aegis128l_update(state: *mut [u8; 128], m0: *const [u8; 16], m1: *const [u8; 16]);

    /// Performs complete AEGIS-128L encryption (in-place).
    ///
    /// # Safety
    /// - All pointers must be valid for their specified lengths
    /// - `plaintext` buffer will be overwritten with ciphertext
    /// - `tag` must point to 16 bytes
    pub unsafe fn aegis128l_encrypt(
        key: *const [u8; 16],
        nonce: *const [u8; 16],
        aad: *const u8,
        aad_len: usize,
        plaintext: *mut u8,
        plaintext_len: usize,
        tag: *mut [u8; 16],
    );

    /// Performs complete AEGIS-128L decryption (in-place).
    ///
    /// # Safety
    /// - All pointers must be valid for their specified lengths
    /// - `ciphertext` buffer will be overwritten with plaintext
    /// - `expected_tag` and `computed_tag` must point to 16 bytes
    pub unsafe fn aegis128l_decrypt(
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

/// AEGIS-128L AEAD with nonce generation.
pub struct Aegis128L<E: EntropySource> {
    nonce_gen: NonceSessionGenerator<E, NONCE_SIZE>,
}

impl<E: EntropySource> Aegis128L<E> {
    /// Key size in bytes
    pub const KEY_SIZE: usize = KEY_SIZE;
    /// Nonce size in bytes
    pub const NONCE_SIZE: usize = NONCE_SIZE;
    /// Authentication tag size in bytes
    pub const TAG_SIZE: usize = TAG_SIZE;

    /// Creates a new AEGIS-128L instance with the provided entropy source.
    pub fn new(entropy: E) -> Self {
        Self {
            nonce_gen: NonceSessionGenerator::new(entropy),
        }
    }
}

impl Default for Aegis128L<SystemEntropySource> {
    fn default() -> Self {
        Self::new(SystemEntropySource {})
    }
}

impl<E> AeadBackend for Aegis128L<E>
where
    E: EntropySource,
{
    type Key = Aegis128LKey;
    type Nonce = Aegis128LNonce;
    type Tag = Aegis128LTag;

    #[inline(always)]
    fn encrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    ) {
        unsafe {
            aegis128l_encrypt(
                key,
                nonce,
                aad.as_ptr(),
                aad.len(),
                data.as_mut_ptr(),
                data.len(),
                tag,
            )
        }
    }

    #[inline(always)]
    fn decrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), AeadError> {
        let mut computed_tag = [0u8; 16];
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
            )
        }

        // Constant-time tag comparison
        if redoubt_util::constant_time_eq(&computed_tag, tag) {
            Ok(())
        } else {
            Err(AeadError::AuthenticationFailed)
        }
    }

    fn generate_nonce(&mut self) -> Result<Self::Nonce, EntropyError> {
        self.nonce_gen.generate_nonce()
    }
}
