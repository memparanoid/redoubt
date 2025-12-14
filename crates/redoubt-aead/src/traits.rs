// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEAD trait definitions.

use redoubt_rand::EntropyError;

use crate::AeadError;

/// Authenticated Encryption with Associated Data (AEAD) backend trait.
///
/// Used internally by concrete AEAD implementations (XChaCha20-Poly1305, AEGIS-128L).
pub trait AeadBackend {
    type Key;
    type Nonce;
    type Tag;

    /// Encrypt plaintext in-place and write authentication tag.
    fn encrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    );

    /// Decrypt ciphertext in-place after verifying authentication tag.
    fn decrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), AeadError>;

    /// Generate a unique nonce for encryption.
    fn generate_nonce(&mut self) -> Result<Self::Nonce, EntropyError>;
}

/// Object-safe AEAD API for generic code and testing.
///
/// This trait exists STRICTLY for testing purposes - specifically to enable
/// mock injection for verifying zeroization guarantees on error paths.
///
/// While this adds complexity to the codebase, we are willing to pay this
/// trade-off because SECURITY AND ZEROIZATION ARE NON-NEGOTIABLE.
///
/// Users should continue using [`Aead`](crate::Aead) directly with its inherent methods.
/// This trait is only needed internally for generic test code.
pub trait AeadApi {
    fn api_encrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError>;

    fn api_decrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError>;

    fn api_generate_nonce(&mut self) -> Result<Vec<u8>, EntropyError>;

    fn api_key_size(&self) -> usize;
    fn api_nonce_size(&self) -> usize;
    fn api_tag_size(&self) -> usize;
}
