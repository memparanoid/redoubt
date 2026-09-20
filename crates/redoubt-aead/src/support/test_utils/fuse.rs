// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_aead_core::AeadError as AeadCoreError;
use redoubt_rand::EntropyError;

use crate::enums::AeadBehaviour;
use crate::errors::AeadError;

/// One behaviour, and how many calls of each operation have gone past it.
///
/// It burns rather than blocks: every call but the one the behaviour names
/// passes through untouched and the operation runs, and the named one is
/// refused exactly once.
///
/// What it refuses with is the shape that operation fails in for real, with an
/// `Injected` inside it. A variant of its own would be a different error from
/// the one it stands for; carrying the marker one level down keeps the shape
/// and still leaves a real failure unable to satisfy a case that asserts the
/// injected one.
pub struct Fuse {
    behaviour: AeadBehaviour,
    encrypted: usize,
    decrypted: usize,
    nonces: usize,
}

impl Fuse {
    pub(crate) fn new(behaviour: AeadBehaviour) -> Self {
        Self {
            behaviour,
            encrypted: 0,
            decrypted: 0,
            nonces: 0,
        }
    }

    pub(crate) fn at_encrypt(&mut self) -> Result<(), AeadError> {
        self.encrypted += 1;

        match self.behaviour {
            AeadBehaviour::FailAtNthEncrypt(nth) if nth == self.encrypted => {
                Err(AeadError::Primitive(AeadCoreError::Injected))
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn at_decrypt(&mut self) -> Result<(), AeadError> {
        self.decrypted += 1;

        match self.behaviour {
            AeadBehaviour::FailAtNthDecrypt(nth) if nth == self.decrypted => {
                Err(AeadError::Primitive(AeadCoreError::Injected))
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn at_generate_nonce(&mut self) -> Result<(), AeadError> {
        self.nonces += 1;

        match self.behaviour {
            AeadBehaviour::FailAtNthGenerateNonce(nth) if nth == self.nonces => {
                Err(AeadError::NonceEntropy(EntropyError::Injected))
            }
            _ => Ok(()),
        }
    }
}
