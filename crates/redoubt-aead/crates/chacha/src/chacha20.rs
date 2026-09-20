// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ChaCha20, both of the ways its nonce and counter are laid out.

use redoubt_aead_core::consts::chacha::{BERNSTEIN_NONCE_SIZE, KEY_SIZE, NONCE_SIZE};
use redoubt_asm::Backend;
use redoubt_zero::RedoubtZero;

use crate::backend::xor;

/// A keystream laid over a buffer the caller already has.
///
/// It holds nothing but where its operations go. A stream cipher applied to a
/// whole buffer keeps no state between calls — no key resident afterwards, no
/// keystream, and nothing to zeroize that is not the backend's own.
#[cfg_attr(test, derive(Clone, Eq, PartialEq, Debug))]
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct ChaCha20 {
    #[fast_zeroize(skip)]
    backend: Backend,
    // Something to test zeroization on drop against.
    #[cfg(test)]
    __marker: [u8; 32],
    #[cfg(test)]
    __sentinel: redoubt_zero::ZeroizeOnDropSentinel,
}

impl ChaCha20 {
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

    /// `data` xored with the keystream of RFC 8439, starting at `counter`.
    ///
    /// Encryption and decryption are the same call: the keystream does not know
    /// which it is doing.
    ///
    /// # Panics
    ///
    /// Where `data` would take the thirty-two bit counter past its end.
    /// Wrapping there would lay the keystream of the first block over the one
    /// after the last, which is the one thing a stream cipher cannot survive —
    /// so it stops rather than answer.
    pub fn xor(
        &self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) {
        xor(self.backend, key, nonce, u64::from(counter), data);
    }

    /// `data` xored with the keystream of Bernstein's original, starting at
    /// `counter`.
    ///
    /// Eight bytes of nonce and sixty-four bits of counter, which is what
    /// OpenSSH speaks.
    ///
    /// # Panics
    ///
    /// Where `data` would take the sixty-four bit counter past its end. Even
    /// a short message can do that when the caller starts near `u64::MAX`.
    pub fn xor_bernstein(
        &self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; BERNSTEIN_NONCE_SIZE],
        counter: u64,
        data: &mut [u8],
    ) {
        xor(self.backend, key, nonce, counter, data);
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
