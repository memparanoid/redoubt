// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! XChaCha20: ChaCha20 under a subkey, so that a nonce can be twenty-four
//! bytes long and be picked at random without anybody counting.

use redoubt_aead_core::consts::chacha::{KEY_SIZE, XNONCE_SIZE};
use redoubt_asm::Backend;
use redoubt_zero::RedoubtZero;

use crate::backend::xxor;

/// A keystream under a key nobody outside the backend ever sees.
///
/// It holds nothing. The subkey the first sixteen bytes of the nonce derive is
/// made and used inside one backend call, so it never crosses back into Rust
/// and there is no second key to keep or to wipe.
#[cfg_attr(test, derive(Clone, Eq, PartialEq, Debug))]
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct XChaCha20 {
    // Something to test zeroization on drop against.
    #[cfg(test)]
    __marker: [u8; 32],
    #[cfg(test)]
    __sentinel: redoubt_zero::ZeroizeOnDropSentinel,
}

impl XChaCha20 {
    /// One ready to be laid over a buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(test)]
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
        backend: Backend,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; XNONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) {
        xxor(backend, key, nonce, u64::from(counter), data);
    }

    /// Something in it that a zeroization has to remove.
    #[cfg(test)]
    pub(crate) fn unzeroize(&mut self) {
        self.__marker = [0xff; 32];
    }
}
