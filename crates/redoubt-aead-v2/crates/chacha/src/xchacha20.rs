// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! XChaCha20: ChaCha20 under a subkey, so that a nonce can be twenty-four
//! bytes long and be picked at random without anybody counting.

use redoubt_aead_v2_core::Backend;
use redoubt_aead_v2_core::consts::chacha::{BLOCK_SIZE, KEY_SIZE, XNONCE_SIZE};

use crate::backend::xxor;

/// A keystream under a key nobody outside the backend ever sees.
///
/// It holds nothing but where its operations go. The subkey the first sixteen
/// bytes of the nonce derive is made and used inside one backend call, so it
/// never crosses back into Rust and there is no second key to keep or to wipe.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XChaCha20 {
    backend: Backend,
}

impl XChaCha20 {
    /// One whose operations go where the target says.
    #[must_use]
    pub fn new() -> Self {
        Self::with_backend(Backend::default())
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
        let blocks = data.len().div_ceil(BLOCK_SIZE) as u64;

        assert!(
            u64::from(counter) + blocks <= u64::from(u32::MAX) + 1,
            "the message runs past the end of the counter"
        );

        xxor(self.backend, key, nonce, u64::from(counter), data);
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
