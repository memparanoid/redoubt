// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L AEAD implementation.

use crate::{AeadBackend, DecryptError};

use super::consts::{Aegis128LKey, Aegis128LNonce, Aegis128LTag};
use super::state;

/// AEGIS-128L AEAD.
///
/// This is a zero-sized wrapper that provides the Aead trait implementation.
/// All state is managed internally using local variables for register optimization.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aegis128L;

impl AeadBackend for Aegis128L {
    type Key = Aegis128LKey;
    type Nonce = Aegis128LNonce;
    type Tag = Aegis128LTag;

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

    fn decrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), DecryptError> {
        if unsafe { state::decrypt(key, nonce, aad, data, tag) } {
            Ok(())
        } else {
            Err(DecryptError::AuthenticationFailed)
        }
    }
}
