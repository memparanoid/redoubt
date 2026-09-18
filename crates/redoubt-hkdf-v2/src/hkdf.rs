// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA256, as the door and the derivation behind it.

use redoubt_asm::Backend;

use crate::backend::hkdf_sha256;
use crate::consts::MAX_OUTPUT_SIZE;
use crate::error::HkdfError;

/// A derivation.
///
/// It holds nothing but where its operations go. It is handed the whole of what
/// it works on and keeps nothing between calls — no key resident afterwards, no
/// chaining state, and nothing to zeroize that is not the backend's own.
///
/// Not public, and neither is anything on it. What a caller wants is [`hkdf`].
/// The steps the derivation is made of are not reached through here: a test
/// that wants one asks the seam, which is where a backend can be named.
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
