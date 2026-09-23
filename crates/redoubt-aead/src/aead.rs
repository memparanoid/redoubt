// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::vec;
use alloc::vec::Vec;

use core::ops::{Deref, DerefMut};

use redoubt_aead_aegis128l::Aegis128L;
use redoubt_aead_core::consts::{aegis, chacha};
use redoubt_aead_core::{AeadDecrypt, AeadEncrypt};
use redoubt_aead_xchachapoly1305::XChaCha20Poly1305;
use redoubt_codec::{BytesRequired, Decode, DecodeError, Encode, RedoubtCodec, RedoubtCodecBuffer};
use redoubt_rand::{NonceGenerator, NonceSessionGenerator, SystemEntropySource};

use crate::enums::AeadAlgorithm;
use crate::errors::AeadError;
use crate::feature_detector::FeatureDetector;
use crate::utils::{aegis_widths, aegis_widths_mut, chacha_widths, chacha_widths_mut};

#[cfg(any(test, feature = "test-utils"))]
use crate::enums::AeadBehaviour;
#[cfg(any(test, feature = "test-utils"))]
use crate::support::test_utils::Fuse;

/// What this machine can run, one field each.
///
/// The shapes differ because the answers differ. XChaCha20-Poly1305 asks
/// nothing of the hardware, so there is never a question to answer about it.
/// AEGIS-128L needs AES instructions, so it arrives as an `Option` — and a
/// caller that unwraps it has, by then, already asked.
pub struct AeadVariants {
    /// Always here.
    pub xchachapoly1305: Aead,
    /// Here where the machine has AES instructions, and nothing otherwise.
    pub aegis128l: Option<Aead>,
}

/// A list of algorithms, on the wire and off it.
///
/// The `Deref` is to the `Vec` underneath, so it reads and is indexed like
/// one; what it adds is the encoding, which is the crate's codec and not a
/// format written here.
#[derive(RedoubtCodec, Default, Clone, Eq, PartialEq, Debug)]
pub struct AeadAlgorithms(Vec<AeadAlgorithm>);

impl AeadAlgorithms {
    /// The bytes of this list, with the buffer emptied behind them.
    pub fn serialize(&mut self) -> Vec<u8> {
        let bytes_required = self
            .encode_bytes_required()
            .expect("Infallible: two algorithms never reach the bytes a payload can encode to");
        let mut buffer = RedoubtCodecBuffer::with_capacity(bytes_required);

        self.encode_into(&mut buffer)
            .expect("Infallible: capacity calculated above");

        buffer.export_as_vec()
    }

    /// The list those bytes carry, with them emptied behind it.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] where the bytes are not a list this crate wrote: a
    /// length that overruns them, or a byte that is no algorithm.
    pub fn deserialize(mut bytes: &mut [u8]) -> Result<Self, DecodeError> {
        let mut made = AeadAlgorithms::default();

        made.decode_from(&mut bytes)?;

        Ok(made)
    }
}

impl From<Vec<AeadAlgorithm>> for AeadAlgorithms {
    fn from(algorithms: Vec<AeadAlgorithm>) -> Self {
        Self(algorithms)
    }
}

impl Deref for AeadAlgorithms {
    type Target = Vec<AeadAlgorithm>;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AeadAlgorithms {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The counter this cipher's nonces are drawn from.
///
/// A variant each because the widths differ, so the generators are different
/// types and no field can hold either.
pub(crate) enum Session {
    XChachaPoly1305(NonceSessionGenerator<SystemEntropySource, { chacha::XNONCE_SIZE }>),
    Aegis128L(NonceSessionGenerator<SystemEntropySource, { aegis::NONCE_SIZE }>),
}

/// An authenticated cipher, chosen and ready to run.
///
/// The key arrives with each call and leaves with it, so there is no secret
/// here to keep or to wipe. What it does hold is where its nonces come from:
/// nonces from one `Aead` cannot collide, and two `Aead`s know nothing of each
/// other. A fresh one per message starts the counter again and gives that up,
/// without anything saying so.
pub struct Aead {
    algorithm: AeadAlgorithm,
    session: Session,
    #[cfg(any(test, feature = "test-utils"))]
    fuse: Option<Fuse>,
}

impl Default for Aead {
    fn default() -> Self {
        Aead::new_with(&FeatureDetector::default())
    }
}

impl Aead {
    /// Which cipher this one runs.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// Bytes of key this one takes.
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.algorithm.key_size()
    }

    /// Bytes of nonce this one takes, which is what [`Aead::generate_nonce`]
    /// answers with.
    #[must_use]
    pub fn nonce_size(&self) -> usize {
        self.algorithm.nonce_size()
    }

    /// Bytes of tag this one writes.
    #[must_use]
    pub fn tag_size(&self) -> usize {
        self.algorithm.tag_size()
    }

    /// A nonce this `Aead` has not given before.
    ///
    /// # Errors
    ///
    /// [`AeadError::NonceEntropy`], where the machine has no randomness to
    /// give.
    pub fn generate_nonce(&mut self) -> Result<Vec<u8>, AeadError> {
        #[cfg(any(test, feature = "test-utils"))]
        {
            if let Some(fuse) = self.fuse.as_mut() {
                fuse.at_generate_nonce()?;
            }
        }

        Aead::generate_nonce_with(&mut self.session)
    }

    pub(crate) fn generate_nonce_with(session: &mut Session) -> Result<Vec<u8>, AeadError> {
        let made = match session {
            Session::XChachaPoly1305(nonces) => nonces.generate_nonce()?.to_vec(),
            Session::Aegis128L(nonces) => nonces.generate_nonce()?.to_vec(),
        };

        Ok(made)
    }

    /// Seals `data` in place and writes the tag.
    ///
    /// # Errors
    ///
    /// A width that is not the one this cipher takes, and nothing else: with
    /// the three widths measured, sealing cannot fail.
    pub fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        #[cfg(any(test, feature = "test-utils"))]
        {
            if let Some(fuse) = self.fuse.as_ref() {
                fuse.at_encrypt()?;
            }
        }

        match self.algorithm {
            AeadAlgorithm::XChachaPoly1305 => {
                let (key, nonce, tag) = chacha_widths_mut(key, nonce, tag)?;
                XChaCha20Poly1305::new().encrypt(key, nonce, aad, data, tag);
            }
            AeadAlgorithm::Aegis128L => {
                let (key, nonce, tag) = aegis_widths_mut(key, nonce, tag)?;
                Aegis128L::new().encrypt(key, nonce, aad, data, tag);
            }
        }

        Ok(())
    }

    /// Opens `data` in place, or empties it.
    ///
    /// # Errors
    ///
    /// [`AeadError::Core`] where the tag is not the one that sealed this
    /// ciphertext, and a width that is not the one this cipher takes.
    pub fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        #[cfg(any(test, feature = "test-utils"))]
        {
            if let Some(fuse) = self.fuse.as_ref() {
                fuse.at_decrypt()?;
            }
        }

        match self.algorithm {
            AeadAlgorithm::XChachaPoly1305 => {
                let (key, nonce, tag) = chacha_widths(key, nonce, tag)?;
                XChaCha20Poly1305::new().decrypt(key, nonce, aad, data, tag)?;
            }
            AeadAlgorithm::Aegis128L => {
                let (key, nonce, tag) = aegis_widths(key, nonce, tag)?;
                Aegis128L::new().decrypt(key, nonce, aad, data, tag)?;
            }
        }

        Ok(())
    }

    pub(crate) fn new_with(feature_detector: &FeatureDetector) -> Self {
        if let Some(aegis) = Aead::new_aegis(feature_detector) {
            return aegis;
        }

        Aead::new_chacha()
    }

    pub(crate) fn new_chacha() -> Self {
        Self {
            algorithm: AeadAlgorithm::XChachaPoly1305,
            session: Session::XChachaPoly1305(NonceSessionGenerator::new(SystemEntropySource {})),
            #[cfg(any(test, feature = "test-utils"))]
            fuse: None,
        }
    }

    pub(crate) fn new_aegis(feature_detector: &FeatureDetector) -> Option<Self> {
        if feature_detector.supports_aes() {
            return Some(Self {
                algorithm: AeadAlgorithm::Aegis128L,
                session: Session::Aegis128L(NonceSessionGenerator::new(SystemEntropySource {})),
                #[cfg(any(test, feature = "test-utils"))]
                fuse: None,
            });
        }

        None
    }

    /// This `Aead`, with one of its calls set to refuse.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_behaviour(mut self, behaviour: AeadBehaviour) -> Self {
        self.fuse = Some(Fuse::new(behaviour));

        self
    }

    /// Every algorithm this machine can run.
    ///
    /// Never empty: XChaCha20-Poly1305 is in it by construction.
    pub fn supported_algorithms() -> AeadAlgorithms {
        Aead::supported_algorithms_with(&FeatureDetector::default())
    }

    pub(crate) fn supported_algorithms_with(feature_detector: &FeatureDetector) -> AeadAlgorithms {
        let mut out = vec![AeadAlgorithm::XChachaPoly1305];

        if feature_detector.supports_aes() {
            out.push(AeadAlgorithm::Aegis128L);
        }

        AeadAlgorithms::from(out)
    }

    /// One of each this machine can run, built and ready.
    ///
    /// Where a caller wants a particular cipher rather than the fastest one:
    /// take the field, or take the `Option` and answer for it being empty.
    pub fn variants() -> AeadVariants {
        Aead::variants_with(&FeatureDetector::default())
    }

    pub(crate) fn variants_with(feature_detector: &FeatureDetector) -> AeadVariants {
        AeadVariants {
            xchachapoly1305: Aead::new_chacha(),
            aegis128l: Aead::new_aegis(feature_detector),
        }
    }

    /// The one this machine has, named rather than chosen.
    ///
    /// Through `variants` and not around it, so that what a test runs is what a
    /// caller would have been handed.
    #[cfg(test)]
    pub(crate) fn from_algorithm(algorithm: AeadAlgorithm) -> Self {
        let variants = Aead::variants();

        match algorithm {
            AeadAlgorithm::XChachaPoly1305 => variants.xchachapoly1305,
            AeadAlgorithm::Aegis128L => variants
                .aegis128l
                .expect("Infallible: this machine has aes"),
        }
    }
}
