// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::sync::atomic::{AtomicUsize, Ordering};

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
///
/// The counts are atomic so that a read can be taken through `&self`, which is
/// what lets one box be read from several threads at once. A `Cell` would
/// count just as well and would cost the type its `Sync`, taking the shared
/// read with it wherever `test-utils` is on.
pub struct Fuse {
    behaviour: AeadBehaviour,
    encrypted: AtomicUsize,
    decrypted: AtomicUsize,
    nonces: AtomicUsize,
}

impl Fuse {
    pub(crate) fn new(behaviour: AeadBehaviour) -> Self {
        Self {
            behaviour,
            encrypted: AtomicUsize::new(0),
            decrypted: AtomicUsize::new(0),
            nonces: AtomicUsize::new(0),
        }
    }

    pub(crate) fn at_encrypt(&self) -> Result<(), AeadError> {
        match self.behaviour {
            AeadBehaviour::FailAtNthEncrypt(nth) if nth == count(&self.encrypted) => {
                Err(AeadError::Primitive(AeadCoreError::Injected))
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn at_decrypt(&self) -> Result<(), AeadError> {
        match self.behaviour {
            AeadBehaviour::FailAtNthDecrypt(nth) if nth == count(&self.decrypted) => {
                Err(AeadError::Primitive(AeadCoreError::Injected))
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn at_generate_nonce(&self) -> Result<(), AeadError> {
        match self.behaviour {
            AeadBehaviour::FailAtNthGenerateNonce(nth) if nth == count(&self.nonces) => {
                Err(AeadError::NonceEntropy(EntropyError::Injected))
            }
            _ => Ok(()),
        }
    }
}

/// This call's ordinal, counting from one.
fn count(counter: &AtomicUsize) -> usize {
    counter.fetch_add(1, Ordering::Relaxed) + 1
}
