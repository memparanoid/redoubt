// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEAD trait definition.

use memrand::EntropyError;

use crate::AeadError;

/// Authenticated Encryption with Associated Data (AEAD) backend trait.
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
