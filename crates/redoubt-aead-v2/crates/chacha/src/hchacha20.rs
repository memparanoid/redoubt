// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HChaCha20, which turns a key and sixteen bytes of nonce into another key.

use redoubt_aead_v2_core::consts::chacha::{HNONCE_SIZE, KEY_SIZE};
use redoubt_asm::Backend;
use redoubt_zero::RedoubtZero;

use crate::backend::subkey;

/// A key derivation that is the ChaCha20 rounds without the addition after
/// them.
///
/// It holds nothing but where its operations go. The subkey is written into
/// storage the caller named and is never kept here.
#[cfg_attr(test, derive(Clone, Eq, PartialEq, Debug))]
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct HChaCha20 {
    #[fast_zeroize(skip)]
    backend: Backend,
    // Something to test zeroization on drop against.
    #[cfg(test)]
    __marker: [u8; 32],
    #[cfg(test)]
    __sentinel: redoubt_zero::ZeroizeOnDropSentinel,
}

impl HChaCha20 {
    /// One whose operations go where the target says.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: Backend::default(),
            #[cfg(test)]
            __marker: Default::default(),
            #[cfg(test)]
            __sentinel: redoubt_zero::ZeroizeOnDropSentinel::default(),
        }
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
        let mut made = Self::new();

        made.backend = backend;

        made
    }

    /// Something in it that a zeroization has to remove.
    #[cfg(test)]
    pub(crate) fn unzeroize(&mut self) {
        self.__marker = [0xff; 32];
    }
}
