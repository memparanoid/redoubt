// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::mem::size_of;

use crate::error::EntropyError;
use crate::traits::{EntropySource, NonceGenerator};

pub(crate) type Counter = u32;

/// A failure injected into [`NonceSessionGenerator`], for a holder that names
/// the concrete type.
///
/// [`MockNonceSessionGenerator`] covers the holder that is generic over
/// [`NonceGenerator`]. One with a `NonceSessionGenerator<E, N>` field has
/// nowhere to put a wrapper, so the injection lives on the type itself.
///
/// [`MockNonceSessionGenerator`]: crate::test_utils::MockNonceSessionGenerator
#[cfg(any(test, feature = "test-utils"))]
#[derive(Default, Clone, Copy, Eq, PartialEq, Debug)]
pub enum NonceSessionGeneratorBehaviour {
    /// Nothing injected.
    #[default]
    None,
    /// [`NonceGenerator::generate_nonce`] answers [`EntropyError::Injected`]
    /// without reaching the entropy source.
    FailAtGenerateNonce,
}

/// Session-based nonce generator with configurable nonce size.
///
/// Generates unique nonces using a hybrid approach:
/// - **Counter prefix**: Incrementing session counter (type `Counter`) with automatic wrapping
/// - **Random suffix**: Remaining bytes filled with cryptographically secure random data
///
/// # Collision resistance
///
/// For a nonce collision to occur, **both** conditions must be satisfied:
/// 1. Counter must wrap (after 2^32 ≈ 4.3 billion nonces)
/// 2. The random suffix must coincidentally repeat
///
/// Even after counter wrapping, the random suffix provides collision resistance.
///
/// For a 16-byte nonce with 4-byte counter (12 random bytes):
/// - Collision probability after wrapping: ~1/2^96 per nonce pair
///
/// For a 24-byte nonce with 4-byte counter (20 random bytes):
/// - Collision probability after wrapping: ~1/2^160 per nonce pair
///
/// # Why hybrid, not purely random
///
/// A purely random nonce only offers a *probabilistic* uniqueness guarantee,
/// bounded by the birthday paradox (~2^64 pairs for a 16-byte nonce). The
/// counter prefix upgrades intra-session uniqueness to a **deterministic**
/// guarantee: the first 2^32 nonces of a session cannot collide, by
/// construction.
///
/// Combined with ephemeral per-session keys (a key never comes close to 2^32
/// uses), the (key, nonce) pair is unique on both axes — the invariant AEAD
/// ciphers require: reusing a (key, nonce) pair breaks confidentiality and
/// integrity, it does not merely degrade them.
///
/// Division of labor: structure guarantees uniqueness, randomness provides
/// unpredictability — each mechanism doing what it actually guarantees.
///
/// # Example
///
/// ```ignore
/// use redoubt_rand::{SystemEntropySource, NonceSessionGenerator, NonceGenerator};
///
/// let entropy = SystemEntropySource {};
/// let mut generator = NonceSessionGenerator::new(entropy);
///
/// let nonce = generator.generate_nonce()?;
/// ```
pub struct NonceSessionGenerator<E: EntropySource, const NONCE_SIZE: usize> {
    #[cfg(any(test, feature = "test-utils"))]
    behaviour: NonceSessionGeneratorBehaviour,
    entropy: E,
    counter: Counter,
    initialized: bool,
}

impl<E: EntropySource, const NONCE_SIZE: usize> NonceSessionGenerator<E, NONCE_SIZE> {
    /// Creates a new nonce session generator.
    ///
    /// The counter is lazily initialized with random bytes on first use
    /// to avoid predictable patterns in memory dumps: a counter starting at
    /// zero is a recognizable fingerprint that also leaks how many nonces
    /// the session has issued. This is deliberate — do not "simplify" it to
    /// a zero-initialized counter.
    ///
    /// # Arguments
    ///
    /// * `entropy` - Entropy source for generating random nonce suffixes
    pub fn new(entropy: E) -> Self {
        Self {
            entropy,
            counter: 0,
            initialized: false,
            #[cfg(any(test, feature = "test-utils"))]
            behaviour: NonceSessionGeneratorBehaviour::default(),
        }
    }

    fn maybe_initialize(&mut self) -> Result<(), EntropyError> {
        if !self.initialized {
            let mut counter_bytes = [0u8; size_of::<Counter>()];

            self.entropy.fill_bytes(&mut counter_bytes)?;
            self.counter = Counter::from_le_bytes(counter_bytes);

            self.initialized = true;
        }

        Ok(())
    }

    /// This generator, carrying `behaviour`.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_behaviour(mut self, behaviour: NonceSessionGeneratorBehaviour) -> Self {
        self.behaviour = behaviour;
        self
    }

    #[cfg(test)]
    pub(crate) fn entropy(&self) -> &E {
        &self.entropy
    }

    #[cfg(test)]
    pub(crate) fn set_counter_for_test(&mut self, counter: Counter) {
        self.counter = counter;
        self.initialized = true;
    }
}

impl<E: EntropySource, const NONCE_SIZE: usize> NonceGenerator<NONCE_SIZE>
    for NonceSessionGenerator<E, NONCE_SIZE>
{
    fn generate_nonce(&mut self) -> Result<[u8; NONCE_SIZE], EntropyError> {
        #[cfg(any(test, feature = "test-utils"))]
        {
            if self.behaviour == NonceSessionGeneratorBehaviour::FailAtGenerateNonce {
                return Err(EntropyError::Injected);
            }
        }

        self.maybe_initialize()?;

        let mut nonce = [0u8; NONCE_SIZE];
        // First part: counter
        nonce[..size_of::<Counter>()].copy_from_slice(&self.counter.to_le_bytes());

        // Second part: fill remaining bytes with random
        self.entropy
            .fill_bytes(&mut nonce[size_of::<Counter>()..])?;

        self.counter = self.counter.wrapping_add(1);

        Ok(nonce)
    }
}
