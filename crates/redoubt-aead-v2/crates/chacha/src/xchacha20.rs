// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! XChaCha20: ChaCha20 under a subkey, so that a nonce can be twenty-four
//! bytes long and be picked at random without anybody counting.

use redoubt_aead_v2_core::consts::chacha::{KEY_SIZE, XNONCE_SIZE};
use redoubt_asm::Backend;
use redoubt_zero::RedoubtZero;

use crate::backend::xxor;

/// A keystream under a key nobody outside the backend ever sees.
///
/// It holds nothing but where its operations go. The subkey the first sixteen
/// bytes of the nonce derive is made and used inside one backend call, so it
/// never crosses back into Rust and there is no second key to keep or to wipe.
#[cfg_attr(test, derive(Clone, Eq, PartialEq, Debug))]
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct XChaCha20 {
    #[fast_zeroize(skip)]
    backend: Backend,
    // Something to test zeroization on drop against.
    #[cfg(any(test, feature = "test-utils"))]
    __marker: [u8; 32],
    #[cfg(test)]
    __sentinel: redoubt_zero::ZeroizeOnDropSentinel,
}

impl XChaCha20 {
    /// One whose operations go where the target says.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: Backend::default(),
            #[cfg(any(test, feature = "test-utils"))]
            __marker: Default::default(),
            #[cfg(test)]
            __sentinel: redoubt_zero::ZeroizeOnDropSentinel::default(),
        }
    }

    /// `data` xored with the keystream, starting at `counter`.
    ///
    /// Encryption and decryption are the same call.
    ///
    /// # Panics
    ///
    /// Where `data` would take the thirty-two bit counter past its end. The
    /// keystream underneath is RFC 8439's, so the bound is RFC 8439's.
    pub fn xor(
        &self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; XNONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) {
        xxor(self.backend, key, nonce, u64::from(counter), data);
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
    #[cfg(any(test, feature = "test-utils"))]
    pub fn unzeroize(&mut self) {
        self.__marker = [0xff; 32];
    }
}
