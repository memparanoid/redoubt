// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! XChaCha20-Poly1305 AEAD implementation (RFC 8439 + draft-irtf-cfrg-xchacha)
//!
//! All sensitive state is zeroized on drop using memzer.

use zeroize::Zeroize;

use memalloc::AllockedVec;
use memutil::u64_to_le;
use memzer::{DropSentinel, MemZer};

use crate::chacha20::XChaCha20;
use crate::consts::{KEY_SIZE, TAG_SIZE};
#[cfg(test)]
use crate::consts::XNONCE_SIZE;
use crate::poly1305::Poly1305;
use crate::types::{AeadKey, XNonce};

/// Errors that can occur during AEAD decryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecryptError {
    #[cfg(test)]
    #[error("invalid nonce size: expected {XNONCE_SIZE} bytes")]
    InvalidNonceSize,

    #[error("ciphertext too short: expected at least {TAG_SIZE} bytes")]
    CiphertextTooShort,

    #[error("authentication failed: tag mismatch")]
    AuthenticationFailed,
}

/// XChaCha20-Poly1305 AEAD with guaranteed zeroization.
#[derive(Zeroize, MemZer)]
#[zeroize(drop)]
pub(crate) struct Aead {
    xchacha: XChaCha20,
    poly: Poly1305,
    poly_key: [u8; KEY_SIZE],
    expected_tag: [u8; TAG_SIZE],
    len_block: [u8; TAG_SIZE],
    output: AllockedVec<u8>,
    __drop_sentinel: DropSentinel,
}

impl Default for Aead {
    fn default() -> Self {
        Self {
            xchacha: XChaCha20::default(),
            poly: Poly1305::default(),
            poly_key: [0; KEY_SIZE],
            expected_tag: [0; TAG_SIZE],
            len_block: [0; TAG_SIZE],
            output: AllockedVec::default(),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl Aead {
    fn compute_tag(&mut self, aad: &[u8], ciphertext: &[u8]) {
        self.poly.init(&self.poly_key);
        self.poly.update_padded(aad);
        self.poly.update_padded(ciphertext);

        let mut aad_len = aad.len() as u64;
        let mut ct_len = ciphertext.len() as u64;
        u64_to_le(
            &mut aad_len,
            (&mut self.len_block[0..8])
                .try_into()
                .expect("infallible: len_block[0..8] is exactly 8 bytes"),
        );
        u64_to_le(
            &mut ct_len,
            (&mut self.len_block[8..16])
                .try_into()
                .expect("infallible: len_block[8..16] is exactly 8 bytes"),
        );
        self.poly.update(&self.len_block);

        self.poly.finalize(&mut self.expected_tag);
        self.len_block.zeroize();
    }

    pub fn encrypt(
        &mut self,
        key: &AeadKey,
        xnonce: &XNonce,
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> AllockedVec<u8> {
        self.xchacha.crypt(key, xnonce, plaintext);

        self.xchacha.generate_poly_key(key, xnonce, &mut self.poly_key);
        self.compute_tag(aad, plaintext);

        self.output
            .reserve_exact(plaintext.len() + TAG_SIZE)
            .expect("infallible: fresh AllockedVec");
        self.output
            .drain_from(plaintext)
            .expect("infallible: capacity reserved");
        self.output
            .drain_from(&mut self.expected_tag)
            .expect("infallible: capacity reserved");

        core::mem::take(&mut self.output)
    }

    pub fn decrypt(
        &mut self,
        key: &AeadKey,
        xnonce: &XNonce,
        aad: &[u8],
        ciphertext_with_tag: &mut [u8],
    ) -> Result<AllockedVec<u8>, DecryptError> {
        if ciphertext_with_tag.len() < TAG_SIZE {
            ciphertext_with_tag.zeroize();
            return Err(DecryptError::CiphertextTooShort);
        }

        let ct_len = ciphertext_with_tag.len() - TAG_SIZE;
        let (ciphertext, received_tag) = ciphertext_with_tag.split_at_mut(ct_len);

        self.xchacha.generate_poly_key(key, xnonce, &mut self.poly_key);
        self.compute_tag(aad, ciphertext);

        if !constant_time_eq(&self.expected_tag, received_tag) {
            ciphertext.zeroize();
            received_tag.zeroize();
            self.poly_key.zeroize();
            self.expected_tag.zeroize();
            return Err(DecryptError::AuthenticationFailed);
        }

        self.xchacha.crypt(key, xnonce, ciphertext);

        self.output
            .reserve_exact(ciphertext.len())
            .expect("infallible: fresh AllockedVec");
        self.output
            .drain_from(ciphertext)
            .expect("infallible: capacity reserved");
        received_tag.zeroize();

        Ok(core::mem::take(&mut self.output))
    }
}

impl core::fmt::Debug for Aead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Aead {{ [protected] }}")
    }
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// Public API

pub fn xchacha20poly1305_encrypt(
    key: &AeadKey,
    xnonce: &XNonce,
    aad: &[u8],
    plaintext: &mut [u8],
) -> AllockedVec<u8> {
    Aead::default().encrypt(key, xnonce, aad, plaintext)
}

pub fn xchacha20poly1305_decrypt(
    key: &AeadKey,
    xnonce: &XNonce,
    aad: &[u8],
    ciphertext_with_tag: &mut [u8],
) -> Result<AllockedVec<u8>, DecryptError> {
    Aead::default().decrypt(key, xnonce, aad, ciphertext_with_tag)
}

#[cfg(test)]
pub(crate) fn xchacha20poly1305_decrypt_slice(
    key: &[u8],
    xnonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &mut [u8],
) -> Result<AllockedVec<u8>, DecryptError> {
    let key: &[u8; KEY_SIZE] = key.try_into().map_err(|_| DecryptError::InvalidNonceSize)?;
    let xnonce: &[u8; XNONCE_SIZE] = xnonce
        .try_into()
        .map_err(|_| DecryptError::InvalidNonceSize)?;
    xchacha20poly1305_decrypt(key, xnonce, aad, ciphertext_with_tag)
}
