// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::mem::size_of;

use crate::traits::{EntropySource, NonceGenerator};

pub(crate) type COUNTER = u32;
/// Session-based nonce generator with configurable nonce size.
///
/// Generates unique nonces using a hybrid approach:
/// - **Counter prefix**: Incrementing session counter (type `COUNTER`) with automatic wrapping
/// - **Random suffix**: Remaining bytes filled with cryptographically secure random data
///
/// # Collision resistance
///
/// For a nonce collision to occur, **both** conditions must be satisfied:
/// 1. Counter must wrap (after 2^32 ≈ 4.3 billion nonces)
/// 2. The random suffix must coincidentally repeat
///
/// Even after counter wrapping, the random suffix provides collision resistance.
/// For a 16-byte nonce with 4-byte counter (12 random bytes):
/// - Collision probability after wrapping: ~1/2^96 per nonce pair
/// For a 24-byte nonce with 4-byte counter (20 random bytes):
/// - Collision probability after wrapping: ~1/2^160 per nonce pair
///
/// # Example
///
/// ```ignore
/// use memrand::{SystemEntropySource, NonceSessionGenerator, NonceGenerator};
///
/// let entropy = SystemEntropySource {};
/// let mut generator = NonceSessionGenerator::new(entropy);
///
/// let nonce = generator.generate_nonce()?;
/// ```
pub struct NonceSessionGenerator<E: EntropySource, const NONCE_SIZE: usize> {
    entropy: E,
    counter: COUNTER,
}

impl<E: EntropySource, const NONCE_SIZE: usize> NonceSessionGenerator<E, NONCE_SIZE> {
    /// Creates a new nonce session generator with counter initialized to 0.
    ///
    /// # Arguments
    ///
    /// * `entropy` - Entropy source for generating random nonce suffixes
    pub fn new(entropy: E) -> Self {
        Self {
            entropy,
            counter: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_counter_for_test(&mut self, counter: COUNTER) {
        self.counter = counter;
    }
}

impl<E: EntropySource, const NONCE_SIZE: usize> NonceGenerator<NONCE_SIZE>
    for NonceSessionGenerator<E, NONCE_SIZE>
{
    fn generate_nonce(&mut self) -> Result<[u8; NONCE_SIZE], crate::EntropyError> {
        let mut nonce = [0u8; NONCE_SIZE];
        // First part: counter
        nonce[..size_of::<COUNTER>()].copy_from_slice(&self.counter.to_le_bytes());

        // Second part: fill remaining bytes with random
        self.entropy
            .fill_bytes(&mut nonce[size_of::<COUNTER>()..])?;

        self.counter = self.counter.wrapping_add(1);

        Ok(nonce)
    }
}
