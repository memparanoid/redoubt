// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;
use crate::session::NonceSessionGenerator;
use crate::traits::{EntropySource, NonceGenerator};

/// Configurable behavior for [`MockNonceSessionGenerator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockNonceSessionGeneratorBehaviour {
    /// Normal operation (delegates to real nonce generator).
    None,
    /// Simulates nonce generation failure.
    FailAtFillBytes,
}

/// Mock nonce generator for testing.
///
/// Wraps [`NonceSessionGenerator`] but allows simulating failures via [`MockNonceSessionGeneratorBehaviour`].
pub struct MockNonceSessionGenerator<E: EntropySource, const NONCE_SIZE: usize> {
    inner: NonceSessionGenerator<E, NONCE_SIZE>,
    behaviour: MockNonceSessionGeneratorBehaviour,
}

impl<E: EntropySource, const NONCE_SIZE: usize> MockNonceSessionGenerator<E, NONCE_SIZE> {
    /// Creates a new mock nonce generator with the specified behavior.
    pub fn new(entropy: E, behaviour: MockNonceSessionGeneratorBehaviour) -> Self {
        Self {
            inner: NonceSessionGenerator::new(entropy),
            behaviour,
        }
    }

    /// Changes the mock behavior at runtime.
    pub fn change_behaviour(&mut self, behaviour: MockNonceSessionGeneratorBehaviour) {
        self.behaviour = behaviour;
    }
}

impl<E: EntropySource, const NONCE_SIZE: usize> NonceGenerator<NONCE_SIZE>
    for MockNonceSessionGenerator<E, NONCE_SIZE>
{
    fn generate_nonce(&mut self) -> Result<[u8; NONCE_SIZE], EntropyError> {
        match self.behaviour {
            MockNonceSessionGeneratorBehaviour::None => self.inner.generate_nonce(),
            MockNonceSessionGeneratorBehaviour::FailAtFillBytes => {
                Err(EntropyError::EntropyNotAvailable)
            }
        }
    }
}
