// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HChaCha20, which turns a key and sixteen bytes of nonce into another key.

use redoubt_aead_v2_core::Backend;
use redoubt_aead_v2_core::consts::chacha::{HNONCE_SIZE, KEY_SIZE};

use crate::backend::subkey;

/// A key derivation that is the ChaCha20 rounds without the addition after
/// them.
///
/// It holds nothing but where its operations go. The subkey is written into
/// storage the caller named and is never kept here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HChaCha20 {
    backend: Backend,
}

impl HChaCha20 {
    /// One whose operations go where the target says.
    #[must_use]
    pub fn new() -> Self {
        Self::with_backend(Backend::default())
    }

    /// The subkey `key` and `nonce` derive, into `out`.
    ///
    /// [`crate::xchacha20::XChaCha20`] does not come through here. What it
    /// needs is the subkey used and not the subkey handed back, and the
    /// difference is whether a second key exists in this crate's memory at all.
    /// This one is for the caller that wants the derivation itself, and for the
    /// vector the draft publishes for it.
    pub fn subkey(
        &self,
        out: &mut [u8; KEY_SIZE],
        key: &[u8; KEY_SIZE],
        nonce: &[u8; HNONCE_SIZE],
    ) {
        subkey(self.backend, out, key, nonce);
    }

    /// One that sends its operations where it is told.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_backend(backend: Backend) -> Self {
        Self { backend }
    }

    /// One whose operations go where the target says, which is the only place
    /// they go outside a test.
    #[cfg(not(any(test, feature = "test-utils")))]
    fn with_backend(backend: Backend) -> Self {
        Self { backend }
    }
}
