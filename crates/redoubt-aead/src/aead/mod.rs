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
//! - **x86_64 (non-Windows) / aarch64 with AES**: Uses AEGIS-128L (hardware-accelerated)
//! - **Otherwise**: Falls back to XChaCha20-Poly1305

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use redoubt_aead_core::{AeadApi, AeadBackend, AeadError, EntropyError};
use redoubt_aead_xchacha::XChacha20Poly1305;

use crate::feature_detector::FeatureDetector;

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
use redoubt_aead_aegis_x86::Aegis128LX86Backend;

#[cfg(target_arch = "aarch64")]
use redoubt_aead_aegis_arm::Aegis128LArmBackend;

/// Internal enum representing the selected backend implementation.
enum AeadBackendImpl {
    #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
    Aegis128LX86(Aegis128LX86Backend),
    #[cfg(target_arch = "aarch64")]
    Aegis128LArm(Aegis128LArmBackend),
    XChacha20Poly1305(Box<XChacha20Poly1305<redoubt_rand::SystemEntropySource>>),
}

/// Backend variant for [`Aead`] construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadVariant {
    /// Automatically select the fastest backend based on CPU capabilities.
    Auto,
    /// Force XChaCha20-Poly1305 regardless of hardware support.
    XChachaPoly1305,
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

impl From<AeadVariant> for Aead {
    fn from(variant: AeadVariant) -> Self {
        match variant {
            AeadVariant::Auto => Self::new(),
            AeadVariant::XChachaPoly1305 => Self {
                backend: AeadBackendImpl::XChacha20Poly1305(Box::default()),
            },
        }
    }
}

impl Aead {
    /// Creates a new AEAD instance with runtime backend selection.
    pub fn new() -> Self {
        let feature_detector = FeatureDetector::new();
        Aead::new_with_feature_detector(feature_detector)
    }

    pub(crate) fn new_with_feature_detector(feature_detector: FeatureDetector) -> Self {
        #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
        if feature_detector.has_aes() {
            return Self {
                backend: AeadBackendImpl::Aegis128LX86(Aegis128LX86Backend),
            };
        }

        #[cfg(target_arch = "aarch64")]
        if feature_detector.has_aes() {
            return Self {
                backend: AeadBackendImpl::Aegis128LArm(Aegis128LArmBackend),
            };
        }

        let _ = feature_detector;

        Self {
            backend: AeadBackendImpl::XChacha20Poly1305(Box::default()),
        }
    }

    /// Returns the name of the selected backend.
    pub fn backend_name(&self) -> &'static str {
        match &self.backend {
            #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
            AeadBackendImpl::Aegis128LX86(_) => "AEGIS-128L",
            #[cfg(target_arch = "aarch64")]
            AeadBackendImpl::Aegis128LArm(_) => "AEGIS-128L",
            AeadBackendImpl::XChacha20Poly1305(_) => "XChaCha20-Poly1305",
        }
    }

    /// Encrypts data in-place and generates an authentication tag.
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
            #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
            AeadBackendImpl::Aegis128LX86(b) => b.api_encrypt(key, nonce, aad, data, tag),
            #[cfg(target_arch = "aarch64")]
            AeadBackendImpl::Aegis128LArm(b) => b.api_encrypt(key, nonce, aad, data, tag),
            AeadBackendImpl::XChacha20Poly1305(b) => {
                let key: &[u8; redoubt_aead_xchacha::KEY_SIZE] =
                    key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
                let nonce: &[u8; redoubt_aead_xchacha::XNONCE_SIZE] =
                    nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
                let tag: &mut [u8; redoubt_aead_xchacha::TAG_SIZE] =
                    tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;
                b.encrypt(key, nonce, aad, data, tag);
                Ok(())
            }
        }
    }

    /// Decrypts data in-place and verifies the authentication tag.
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
            #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
            AeadBackendImpl::Aegis128LX86(b) => b.api_decrypt(key, nonce, aad, data, tag),
            #[cfg(target_arch = "aarch64")]
            AeadBackendImpl::Aegis128LArm(b) => b.api_decrypt(key, nonce, aad, data, tag),
            AeadBackendImpl::XChacha20Poly1305(b) => {
                let key: &[u8; redoubt_aead_xchacha::KEY_SIZE] =
                    key.try_into().map_err(|_| AeadError::InvalidKeySize)?;
                let nonce: &[u8; redoubt_aead_xchacha::XNONCE_SIZE] =
                    nonce.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
                let tag: &[u8; redoubt_aead_xchacha::TAG_SIZE] =
                    tag.try_into().map_err(|_| AeadError::InvalidTagSize)?;
                b.decrypt(key, nonce, aad, data, tag)
            }
        }
    }

    /// Generates a cryptographically secure random nonce.
    #[inline]
    pub fn generate_nonce(&mut self) -> Result<Vec<u8>, EntropyError> {
        match &mut self.backend {
            #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
            AeadBackendImpl::Aegis128LX86(b) => b.api_generate_nonce(),
            #[cfg(target_arch = "aarch64")]
            AeadBackendImpl::Aegis128LArm(b) => b.api_generate_nonce(),
            AeadBackendImpl::XChacha20Poly1305(b) => b
                .generate_nonce()
                .map(|n: [u8; redoubt_aead_xchacha::XNONCE_SIZE]| n.to_vec()),
        }
    }

    /// Returns the key size in bytes for the selected backend.
    #[inline]
    pub fn key_size(&self) -> usize {
        match &self.backend {
            #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
            AeadBackendImpl::Aegis128LX86(b) => b.api_key_size(),
            #[cfg(target_arch = "aarch64")]
            AeadBackendImpl::Aegis128LArm(b) => b.api_key_size(),
            AeadBackendImpl::XChacha20Poly1305(_) => redoubt_aead_xchacha::KEY_SIZE,
        }
    }

    /// Returns the nonce size in bytes for the selected backend.
    #[inline]
    pub fn nonce_size(&self) -> usize {
        match &self.backend {
            #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
            AeadBackendImpl::Aegis128LX86(b) => b.api_nonce_size(),
            #[cfg(target_arch = "aarch64")]
            AeadBackendImpl::Aegis128LArm(b) => b.api_nonce_size(),
            AeadBackendImpl::XChacha20Poly1305(_) => redoubt_aead_xchacha::XNONCE_SIZE,
        }
    }

    /// Returns the tag size in bytes for the selected backend.
    #[inline]
    pub fn tag_size(&self) -> usize {
        match &self.backend {
            #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
            AeadBackendImpl::Aegis128LX86(b) => b.api_tag_size(),
            #[cfg(target_arch = "aarch64")]
            AeadBackendImpl::Aegis128LArm(b) => b.api_tag_size(),
            AeadBackendImpl::XChacha20Poly1305(_) => redoubt_aead_xchacha::TAG_SIZE,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_xchacha20poly1305() -> Self {
        Self {
            backend: AeadBackendImpl::XChacha20Poly1305(Box::default()),
        }
    }

    #[cfg(test)]
    #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
    pub(crate) fn with_aegis128l() -> Self {
        Self {
            backend: AeadBackendImpl::Aegis128LX86(Aegis128LX86Backend),
        }
    }

    #[cfg(test)]
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn with_aegis128l() -> Self {
        Self {
            backend: AeadBackendImpl::Aegis128LArm(Aegis128LArmBackend),
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
    ) -> Result<(), AeadError> {
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
        self.decrypt(key, nonce, aad, data, tag)
    }

    #[inline(always)]
    fn api_generate_nonce(&mut self) -> Result<Vec<u8>, EntropyError> {
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
