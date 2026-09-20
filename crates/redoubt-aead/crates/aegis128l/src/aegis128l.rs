// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The seam between the traits and the two routines.
//!
//! Nothing is computed here. Both operations are one call each, and what this
//! file owns is the comparison after the second one — which is the whole of the
//! difference between a decryption and an opening.

use redoubt_aead_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use redoubt_aead_core::{AeadDecrypt, AeadEncrypt, AeadError, AeadSizes, constant_time_eq};
use redoubt_zero::FastZeroizable;

use crate::asm;

/// AEGIS-128L: one key, one nonce, one message.
///
/// It holds nothing. The state lives in the vector registers for the length of
/// a call and the assembly empties them before it returns; the key arrives at
/// each call and leaves with it. So there is no `Drop` here and nothing for one
/// to do.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Aegis128L;

impl Aegis128L {
    /// One.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl AeadSizes for Aegis128L {
    type Key = [u8; KEY_SIZE];
    type Nonce = [u8; NONCE_SIZE];
    type Tag = [u8; TAG_SIZE];
}

impl AeadEncrypt for Aegis128L {
    fn encrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    ) {
        asm::encrypt(key, nonce, aad, data, tag);
    }
}

impl AeadDecrypt for Aegis128L {
    /// # Errors
    ///
    /// [`AeadError::AuthenticationFailed`] where the tag is not the one that
    /// sealed this ciphertext, and `data` is emptied before it is returned.
    ///
    /// That wipe is load-bearing rather than hygiene. AEGIS is one pass:
    /// deciphering and computing the tag are the same walk of the state, so the
    /// plaintext is in the caller's buffer before there is a tag to compare.
    /// Without it, a message under an invented tag leaves its plaintext there
    /// for a caller that ignores the error.
    fn decrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), AeadError> {
        let mut expected = [0u8; TAG_SIZE];

        asm::decrypt(key, nonce, aad, data, &mut expected);

        let same = constant_time_eq(&expected, tag);

        // On both paths: it is a tag this key produced, and whether it matched
        // says nothing about whether it should stay on the stack.
        expected.fast_zeroize();

        if !same {
            data.fast_zeroize();

            return Err(AeadError::AuthenticationFailed);
        }

        Ok(())
    }
}
