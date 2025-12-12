// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Runtime CPU feature detection for optimal AEAD backend selection.
//!
//! This module provides the [`Aead`] struct which automatically selects
//! the best available AEAD implementation based on:
//! - Target platform (WASI vs native)
//! - CPU features (AES-NI/ARM Crypto Extensions)
//!
//! ## Backend Selection
//!
//! - **WASI**: Always uses XChaCha20-Poly1305 (pure software)
//! - **x86_64/aarch64 with AES**: Uses AEGIS-128L (hardware-accelerated)
//! - **Otherwise**: Falls back to XChaCha20-Poly1305

use memrand::{EntropyError, SystemEntropySource};

use crate::error::AeadError;
use crate::feature_detector::FeatureDetector;
use crate::traits::{AeadApi, AeadBackend};

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "wasi")
))]
use crate::aegis::aegis128l::consts::{
    KEY_SIZE as AEGIS_KEY_SIZE, NONCE_SIZE as AEGIS_NONCE_SIZE, TAG_SIZE as AEGIS_TAG_SIZE,
};

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "wasi")
))]
use crate::aegis::Aegis128L;

use crate::xchacha20poly1305::XChacha20Poly1305;
use crate::xchacha20poly1305::consts::{
    KEY_SIZE as XCHACHA_KEY_SIZE, TAG_SIZE as XCHACHA_TAG_SIZE, XNONCE_SIZE as XCHACHA_NONCE_SIZE,
};

/// Internal enum representing the selected backend implementation.
enum AeadBackendImpl {
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(target_os = "wasi")
    ))]
    Aegis128L(Aegis128L<SystemEntropySource>),
    XChacha20Poly1305(XChacha20Poly1305<SystemEntropySource>),
}

/// AEAD with automatic backend selection based on CPU capabilities.
///
/// Provides a unified interface for authenticated encryption with associated data,
/// automatically selecting the fastest available implementation.
pub struct Aead {
    backend: AeadBackendImpl,
}

impl Default for Aead {
    fn default() -> Self {
        Self::new()
    }
}

impl Aead {
    #[inline(always)]
    pub(crate) fn new_with_feature_detector(feature_detector: FeatureDetector) -> Self {
        #[cfg(target_os = "wasi")]
        {
            Self {
                backend: AeadBackendImpl::XChacha20Poly1305(XChacha20Poly1305::default()),
            }
        }

        #[cfg(not(target_os = "wasi"))]
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            if feature_detector.has_aes() {
                Self {
                    backend: AeadBackendImpl::Aegis128L(Aegis128L::default()),
                }
            } else {
                Self {
                    backend: AeadBackendImpl::XChacha20Poly1305(XChacha20Poly1305::default()),
                }
            }
        }

        #[cfg(not(target_os = "wasi"))]
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self {
                backend: AeadBackendImpl::XChacha20Poly1305(XChacha20Poly1305::default()),
            }
        }
    }

    /// Creates a new AEAD instance with runtime backend selection.
    ///
    /// # Backend Selection Logic
    ///
    /// - **WASI**: Always XChaCha20-Poly1305
    /// - **x86_64**: Checks for AES-NI
    /// - **aarch64**: Checks for ARM Crypto Extensions
    /// - **Other architectures**: XChaCha20-Poly1305
    pub fn new() -> Self {
        let feature_detector = FeatureDetector::new();
        Aead::new_with_feature_detector(feature_detector)
    }

    pub(crate) fn backend_name(&self) -> &'static str {
        match &self.backend {
            #[cfg(all(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                not(target_os = "wasi")
            ))]
            AeadBackendImpl::Aegis128L(_) => "AEGIS-128L",
            AeadBackendImpl::XChacha20Poly1305(_) => "XChaCha20-Poly1305",
        }
    }

    /// Encrypts data in-place and generates an authentication tag.
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key (16 bytes for AEGIS-128L, 32 bytes for XChaCha20-Poly1305)
    /// * `nonce` - Nonce (16 bytes for AEGIS-128L, 24 bytes for XChaCha20-Poly1305)
    /// * `aad` - Additional authenticated data
    /// * `data` - Plaintext to encrypt (modified in-place to ciphertext)
    /// * `tag` - Output authentication tag (16 bytes)
    ///
    /// # Errors
    ///
    /// Returns [`AeadError::InvalidKeySize`], [`AeadError::InvalidNonceSize`], or
    /// [`AeadError::InvalidTagSize`] if slice sizes don't match the selected backend's requirements.
    #[inline(always)]
    pub fn encrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        match &mut self.backend {
            #[cfg(all(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                not(target_os = "wasi")
            ))]
            AeadBackendImpl::Aegis128L(backend) => {
                let key: &[u8; AEGIS_KEY_SIZE] =
                    key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
                let nonce: &[u8; AEGIS_NONCE_SIZE] =
                    nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
                let tag_out: &mut [u8; AEGIS_TAG_SIZE] =
                    tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;
                backend.encrypt(key, nonce, aad, data, tag_out);
                Ok(())
            }
            AeadBackendImpl::XChacha20Poly1305(backend) => {
                let key: &[u8; XCHACHA_KEY_SIZE] =
                    key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
                let nonce: &[u8; XCHACHA_NONCE_SIZE] =
                    nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
                let tag_out: &mut [u8; XCHACHA_TAG_SIZE] =
                    tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;
                backend.encrypt(key, nonce, aad, data, tag_out);
                Ok(())
            }
        }
    }

    /// Decrypts data in-place and verifies the authentication tag.
    ///
    /// # Arguments
    ///
    /// * `key` - Decryption key (16 bytes for AEGIS-128L, 32 bytes for XChaCha20-Poly1305)
    /// * `nonce` - Nonce (16 bytes for AEGIS-128L, 24 bytes for XChaCha20-Poly1305)
    /// * `aad` - Additional authenticated data
    /// * `data` - Ciphertext to decrypt (modified in-place to plaintext)
    /// * `tag` - Authentication tag to verify (16 bytes)
    ///
    /// # Errors
    ///
    /// Returns [`AeadError::AuthenticationFailed`] if tag verification fails.
    /// Returns [`AeadError::InvalidKeySize`], [`AeadError::InvalidNonceSize`], or
    /// [`AeadError::InvalidTagSize`] if slice sizes don't match the selected backend's requirements.
    #[inline(always)]
    pub fn decrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        match &mut self.backend {
            #[cfg(all(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                not(target_os = "wasi")
            ))]
            AeadBackendImpl::Aegis128L(backend) => {
                let key: &[u8; AEGIS_KEY_SIZE] =
                    key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
                let nonce: &[u8; AEGIS_NONCE_SIZE] =
                    nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
                let tag_ref: &[u8; AEGIS_TAG_SIZE] =
                    tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;
                backend.decrypt(key, nonce, aad, data, tag_ref)
            }
            AeadBackendImpl::XChacha20Poly1305(backend) => {
                let key: &[u8; XCHACHA_KEY_SIZE] =
                    key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
                let nonce: &[u8; XCHACHA_NONCE_SIZE] =
                    nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
                let tag_ref: &[u8; XCHACHA_TAG_SIZE] =
                    tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;
                backend.decrypt(key, nonce, aad, data, tag_ref)
            }
        }
    }

    /// Generates a cryptographically secure random nonce.
    ///
    /// Returns a Vec with the appropriate size for the selected backend:
    /// - AEGIS-128L: 16 bytes
    /// - XChaCha20-Poly1305: 24 bytes
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] if the entropy source fails.
    #[inline]
    pub fn generate_nonce(&mut self) -> Result<Vec<u8>, EntropyError> {
        match &mut self.backend {
            #[cfg(all(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                not(target_os = "wasi")
            ))]
            AeadBackendImpl::Aegis128L(backend) => backend.generate_nonce().map(|n| n.to_vec()),
            AeadBackendImpl::XChacha20Poly1305(backend) => {
                backend.generate_nonce().map(|n| n.to_vec())
            }
        }
    }

    /// Returns the key size in bytes for the selected backend.
    #[inline]
    pub fn key_size(&self) -> usize {
        match &self.backend {
            #[cfg(all(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                not(target_os = "wasi")
            ))]
            AeadBackendImpl::Aegis128L(_) => AEGIS_KEY_SIZE,
            AeadBackendImpl::XChacha20Poly1305(_) => XCHACHA_KEY_SIZE,
        }
    }

    /// Returns the nonce size in bytes for the selected backend.
    #[inline]
    pub fn nonce_size(&self) -> usize {
        match &self.backend {
            #[cfg(all(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                not(target_os = "wasi")
            ))]
            AeadBackendImpl::Aegis128L(_) => AEGIS_NONCE_SIZE,
            AeadBackendImpl::XChacha20Poly1305(_) => XCHACHA_NONCE_SIZE,
        }
    }

    /// Returns the tag size in bytes for the selected backend.
    #[inline]
    pub fn tag_size(&self) -> usize {
        match &self.backend {
            #[cfg(all(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                not(target_os = "wasi")
            ))]
            AeadBackendImpl::Aegis128L(_) => AEGIS_TAG_SIZE,
            AeadBackendImpl::XChacha20Poly1305(_) => XCHACHA_TAG_SIZE,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_xchacha20poly1305() -> Self {
        Self {
            backend: AeadBackendImpl::XChacha20Poly1305(XChacha20Poly1305::default()),
        }
    }

    #[cfg(test)]
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(target_os = "wasi")
    ))]
    pub(crate) fn with_aegis128l() -> Self {
        Self {
            backend: AeadBackendImpl::Aegis128L(Aegis128L::default()),
        }
    }
}

impl core::fmt::Debug for Aead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Aead {{ backend: {} }}", self.backend_name())
    }
}

impl AeadApi for Aead {
    #[inline(always)]
    fn api_encrypt(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), crate::AeadError> {
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
    ) -> Result<(), crate::AeadError> {
        self.decrypt(key, nonce, aad, data, tag)
    }

    #[inline(always)]
    fn api_generate_nonce(&mut self) -> Result<Vec<u8>, memrand::EntropyError> {
        self.generate_nonce()
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
