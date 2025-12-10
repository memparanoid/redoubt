// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L AEAD implementation.

use memrand::{
    EntropyError, EntropySource, NonceGenerator, NonceSessionGenerator, SystemEntropySource,
};

use crate::error::AeadError;
use crate::traits::AeadBackend;

use super::consts::{Aegis128LKey, Aegis128LNonce, Aegis128LTag, NONCE_SIZE};
use super::state;

/// AEGIS-128L AEAD with nonce generation.
pub struct Aegis128L<E: EntropySource> {
    nonce_gen: NonceSessionGenerator<E, NONCE_SIZE>,
}

impl<E: EntropySource> Aegis128L<E> {
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
        unsafe { state::encrypt(key, nonce, aad, data, tag) }
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
        if unsafe { state::decrypt(key, nonce, aad, data, tag) } {
            Ok(())
        } else {
            Err(AeadError::AuthenticationFailed)
        }
    }

    fn generate_nonce(&mut self) -> Result<Self::Nonce, EntropyError> {
        self.nonce_gen.generate_nonce()
    }
}
