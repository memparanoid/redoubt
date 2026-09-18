// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA256 and the three steps it is made of, each reachable on its own.

use redoubt_asm::Backend;

use crate::backend::{hkdf_sha256, hmac_sha256, sha256_compress_block, sha256_hash};
use crate::consts::{BLOCK_SIZE, HASH_SIZE, MAX_OUTPUT_SIZE};
use crate::error::HkdfError;

/// A derivation, and the hash and authenticator under it.
///
/// It holds nothing but where its operations go. Every one of them is handed
/// the whole of what it works on and keeps nothing between calls — no key
/// resident afterwards, no chaining state, and nothing to zeroize that is not
/// the backend's own.
///
/// Not public, and neither is anything on it. What a caller wants is [`hkdf`];
/// the three steps under it are here so that each can be asked of either
/// backend and held to the answers its own standard publishes.
#[cfg_attr(test, derive(Clone, Eq, PartialEq, Debug))]
#[derive(Default)]
pub(crate) struct HkdfSha256 {
    backend: Backend,
}

impl HkdfSha256 {
    /// One whose operations go where the target says.
    pub(crate) fn new() -> Self {
        Self {
            backend: Backend::default(),
        }
    }

    /// One block folded into the state somebody else is carrying.
    ///
    /// The state arrives and leaves through the same eight words. What a caller
    /// does between blocks is its own business, and what it is holding is never
    /// copied out to be handed back.
    pub(crate) fn compress_block(&self, h: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {
        sha256_compress_block(self.backend, h, block);
    }

    /// The digest of a message of any length, FIPS 180-4.
    pub(crate) fn hash(&self, data: &[u8], out: &mut [u8; HASH_SIZE]) {
        sha256_hash(self.backend, data, out);
    }

    /// HMAC-SHA256, RFC 2104.
    pub(crate) fn hmac(&self, key: &[u8], data: &[u8], out: &mut [u8; HASH_SIZE]) {
        hmac_sha256(self.backend, key, data, out);
    }

    /// `okm` filled with key material derived from `ikm`, RFC 5869.
    ///
    /// Extract and expand in one call, so that the pseudorandom key the first
    /// produces is made and used without coming back across the seam.
    ///
    /// # Errors
    ///
    /// [`HkdfError::OutputTooLong`] where more output is asked for than the
    /// counter has blocks. RFC 5869 §2.3 counts them with one byte that starts
    /// at one, so the ceiling is two hundred and fifty-five digests. Answering
    /// past it would mean a counter that wrapped, and a caller reading key
    /// material that repeats.
    pub(crate) fn derive(
        &self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        if okm.len() > MAX_OUTPUT_SIZE {
            return Err(HkdfError::OutputTooLong);
        }

        if okm.is_empty() {
            return Ok(());
        }

        hkdf_sha256(self.backend, salt, ikm, info, okm);

        Ok(())
    }

    /// Where its operations go, named after it was built.
    ///
    /// The choice does not belong in the constructor beside the material.
    #[cfg(test)]
    pub(crate) fn set_backend(&mut self, backend: Backend) {
        self.backend = backend;
    }

    /// Where its operations go, named while it is being built.
    #[cfg(test)]
    pub(crate) fn with_backend(mut self, backend: Backend) -> Self {
        self.set_backend(backend);
        self
    }
}

/// `okm` filled with key material derived from `ikm`, RFC 5869.
///
/// The whole of what this crate publishes. It holds nothing, so there is
/// nothing for a caller to keep, and where its work happens is the target's to
/// decide.
///
/// # Errors
///
/// [`HkdfError::OutputTooLong`] where more output is asked for than the counter
/// has blocks, which is two hundred and fifty-five digests.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
    HkdfSha256::new().derive(salt, ikm, info, okm)
}
