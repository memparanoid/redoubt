// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Mock AEAD for testing.

use core::cell::Cell;
use memrand::{EntropyError, SystemEntropySource};

use crate::error::AeadError;
use crate::traits::{AeadApi, AeadBackend};
use crate::xchacha20poly1305::XChacha20Poly1305;
use crate::xchacha20poly1305::{KEY_SIZE, TAG_SIZE, XNONCE_SIZE};

/// Mock failure behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadMockBehaviour {
    /// No failure.
    None,
    /// Fail encrypt at call index (0-indexed).
    FailEncryptAt(usize),
    /// Fail decrypt at call index (0-indexed).
    FailDecryptAt(usize),
    /// Fail nonce generation at call index (0-indexed).
    FailGenerateNonceAt(usize),
}

/// Mock AEAD backed by real XChaCha20-Poly1305.
pub struct AeadMock {
    backend: XChacha20Poly1305<SystemEntropySource>,
    behaviour: AeadMockBehaviour,
    encrypt_count: Cell<usize>,
    decrypt_count: Cell<usize>,
    generate_nonce_count: Cell<usize>,
}

impl AeadMock {
    pub const KEY_SIZE: usize = KEY_SIZE;
    pub const NONCE_SIZE: usize = XNONCE_SIZE;
    pub const TAG_SIZE: usize = TAG_SIZE;

    pub fn new(behaviour: AeadMockBehaviour) -> Self {
        Self {
            backend: XChacha20Poly1305::default(),
            behaviour,
            encrypt_count: Cell::new(0),
            decrypt_count: Cell::new(0),
            generate_nonce_count: Cell::new(0),
        }
    }

    pub fn encrypt(
        &mut self,
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> Result<(), AeadError> {
        let current = self.encrypt_count.get();
        self.encrypt_count.set(current + 1);

        if let AeadMockBehaviour::FailEncryptAt(idx) = self.behaviour {
            if current == idx {
                return Err(AeadError::AuthenticationFailed);
            }
        }

        self.backend.encrypt(key, nonce, aad, data, tag);
        Ok(())
    }

    pub fn decrypt(
        &mut self,
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; Self::TAG_SIZE],
    ) -> Result<(), AeadError> {
        let current = self.decrypt_count.get();
        self.decrypt_count.set(current + 1);

        if let AeadMockBehaviour::FailDecryptAt(idx) = self.behaviour {
            if current == idx {
                return Err(AeadError::AuthenticationFailed);
            }
        }

        self.backend.decrypt(key, nonce, aad, data, tag)
    }

    pub fn generate_nonce(&mut self) -> Result<[u8; Self::NONCE_SIZE], EntropyError> {
        let current = self.generate_nonce_count.get();
        self.generate_nonce_count.set(current + 1);

        if let AeadMockBehaviour::FailGenerateNonceAt(idx) = self.behaviour {
            if current == idx {
                return Err(EntropyError::EntropyNotAvailable);
            }
        }

        self.backend.generate_nonce()
    }

    #[inline]
    pub fn key_size(&self) -> usize {
        Self::KEY_SIZE
    }

    #[inline]
    pub fn nonce_size(&self) -> usize {
        Self::NONCE_SIZE
    }

    #[inline]
    pub fn tag_size(&self) -> usize {
        Self::TAG_SIZE
    }
}

impl AeadApi for AeadMock {
    #[inline(always)]
    fn api_encrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        let key: &[u8; Self::KEY_SIZE] = key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
        let nonce: &[u8; Self::NONCE_SIZE] =
            nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
        let tag: &mut [u8; Self::TAG_SIZE] =
            tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;
        self.encrypt(key, nonce, aad, data, tag)
    }

    #[inline(always)]
    fn api_decrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        let key: &[u8; Self::KEY_SIZE] = key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
        let nonce: &[u8; Self::NONCE_SIZE] =
            nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
        let tag: &[u8; Self::TAG_SIZE] = tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;
        self.decrypt(key, nonce, aad, data, tag)
    }

    #[inline(always)]
    fn api_generate_nonce(&mut self) -> Result<Vec<u8>, EntropyError> {
        self.generate_nonce().map(|n| n.to_vec())
    }

    #[inline(always)]
    fn api_key_size(&self) -> usize {
        self.key_size()
    }

    #[inline(always)]
    fn api_nonce_size(&self) -> usize {
        self.nonce_size()
    }

    #[inline(always)]
    fn api_tag_size(&self) -> usize {
        self.tag_size()
    }
}
