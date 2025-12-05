// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! XChaCha20-Poly1305 AEAD implementation (RFC 8439 + draft-irtf-cfrg-xchacha)
//!
//! All sensitive state is zeroized on drop using memzer.

use memutil::{constant_time_eq, u64_to_le};
use memzer::{DropSentinel, FastZeroizable, MemZer};

use crate::{AeadBackend, DecryptError};

use super::chacha20::XChaCha20;
use super::consts::{KEY_SIZE, TAG_SIZE};
use super::poly1305::Poly1305;
use super::types::{AeadKey, XNonce};

/// XChaCha20-Poly1305 AEAD with guaranteed zeroization.
#[derive(MemZer)]
#[memzer(drop)]
pub struct XChacha20Poly1305 {
    xchacha: XChaCha20,
    poly: Poly1305,
    poly_key: [u8; KEY_SIZE],
    expected_tag: [u8; TAG_SIZE],
    len_block: [u8; TAG_SIZE],
    __drop_sentinel: DropSentinel,
}

impl Default for XChacha20Poly1305 {
    fn default() -> Self {
        Self {
            xchacha: XChaCha20::default(),
            poly: Poly1305::default(),
            poly_key: [0; KEY_SIZE],
            expected_tag: [0; TAG_SIZE],
            len_block: [0; TAG_SIZE],
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl XChacha20Poly1305 {
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
        self.len_block.fast_zeroize();
    }
}

impl AeadBackend for XChacha20Poly1305 {
    type Key = AeadKey;
    type Nonce = XNonce;
    type Tag = [u8; TAG_SIZE];

    fn encrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    ) {
        self.xchacha.crypt(key, nonce, data);

        self.xchacha
            .generate_poly_key(key, nonce, &mut self.poly_key);
        self.compute_tag(aad, data);

        tag.copy_from_slice(&self.expected_tag);
        self.expected_tag.fast_zeroize();
    }

    fn decrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), DecryptError> {
        self.xchacha
            .generate_poly_key(key, nonce, &mut self.poly_key);
        self.compute_tag(aad, data);

        if !constant_time_eq(&self.expected_tag, tag) {
            data.fast_zeroize();
            self.poly_key.fast_zeroize();
            self.expected_tag.fast_zeroize();
            return Err(DecryptError::AuthenticationFailed);
        }

        self.xchacha.crypt(key, nonce, data);
        self.expected_tag.fast_zeroize();

        Ok(())
    }
}

impl core::fmt::Debug for XChacha20Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "XChacha20Poly1305 {{ [protected] }}")
    }
}
