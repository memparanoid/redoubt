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
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadMockBehaviour {
    /// No failure.
    #[default]
    None,
    /// Fail encrypt at call index (0-indexed).
    FailEncryptAt(usize),
    /// Fail decrypt at call index (0-indexed).
    FailDecryptAt(usize),
    /// Fail nonce generation at call index (0-indexed).
    FailGenerateNonceAt(usize),
}

/// Mock AEAD backed by real XChaCha20-Poly1305.
#[derive(Default)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_none_roundtrip() {
        let mut mock = AeadMock::new(AeadMockBehaviour::None);
        let key = [0u8; AeadMock::KEY_SIZE];
        let nonce = mock.generate_nonce().unwrap();
        let original = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut data = original;
        let mut tag = [0u8; AeadMock::TAG_SIZE];

        mock.encrypt(&key, &nonce, &[], &mut data, &mut tag)
            .unwrap();
        assert_ne!(data, original);

        mock.decrypt(&key, &nonce, &[], &mut data, &tag).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_mock_sizes() {
        let mock = AeadMock::new(AeadMockBehaviour::None);
        assert_eq!(mock.key_size(), 32);
        assert_eq!(mock.nonce_size(), 24);
        assert_eq!(mock.tag_size(), 16);
    }

    #[test]
    fn test_mock_fail_encrypt_at_index() {
        let mut mock = AeadMock::new(AeadMockBehaviour::FailEncryptAt(2));
        let key = [0u8; AeadMock::KEY_SIZE];
        let nonce = [0u8; AeadMock::NONCE_SIZE];
        let mut data = [1, 2, 3, 4];
        let mut tag = [0u8; AeadMock::TAG_SIZE];

        assert!(mock.encrypt(&key, &nonce, &[], &mut data, &mut tag).is_ok());
        assert!(mock.encrypt(&key, &nonce, &[], &mut data, &mut tag).is_ok());
        assert!(
            mock.encrypt(&key, &nonce, &[], &mut data, &mut tag)
                .is_err()
        );
        assert!(mock.encrypt(&key, &nonce, &[], &mut data, &mut tag).is_ok());
    }

    #[test]
    fn test_mock_fail_decrypt_at_index() {
        let mut mock = AeadMock::new(AeadMockBehaviour::FailDecryptAt(1));
        let key = [0u8; AeadMock::KEY_SIZE];
        let nonce = mock.generate_nonce().unwrap();
        let original = [1u8, 2, 3, 4];
        let mut data = original;
        let mut tag = [0u8; AeadMock::TAG_SIZE];

        mock.encrypt(&key, &nonce, &[], &mut data, &mut tag)
            .unwrap();
        let ciphertext = data;

        // First decrypt succeeds
        data = ciphertext;
        assert!(mock.decrypt(&key, &nonce, &[], &mut data, &tag).is_ok());

        // Second decrypt fails (at index 1)
        data = ciphertext;
        assert!(mock.decrypt(&key, &nonce, &[], &mut data, &tag).is_err());

        // Third decrypt succeeds again
        data = ciphertext;
        assert!(mock.decrypt(&key, &nonce, &[], &mut data, &tag).is_ok());
    }

    #[test]
    fn test_mock_fail_generate_nonce_at_index() {
        let mut mock = AeadMock::new(AeadMockBehaviour::FailGenerateNonceAt(0));

        assert!(mock.generate_nonce().is_err());
        assert!(mock.generate_nonce().is_ok());
    }
}
