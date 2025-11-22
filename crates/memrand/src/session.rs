// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{EntropySource, XNonceGenerator};

/// Session-based XChaCha20 nonce generator with 192-bit output.
///
/// Generates unique nonces using a hybrid approach:
/// - **128-bit random prefix**: Regenerated for each nonce via [`EntropySource`]
/// - **64-bit counter**: Incrementing session counter with automatic wrapping
///
/// # Collision resistance
///
/// Even with counter wrapping (after 2^64 nonces ≈ 584 years @ 10^9 ops/sec),
/// collision probability remains ~1/2^128 due to the random prefix.
///
/// # Example
///
/// ```ignore
/// use memrand::{SystemEntropySource, XNonceSessionGenerator, XNonceGenerator};
///
/// let entropy = SystemEntropySource {};
/// let mut generator = XNonceSessionGenerator::new(&entropy);
///
/// let mut nonce = [0u8; 24];
/// generator.fill_current_xnonce(&mut nonce)?;
/// ```
pub struct XNonceSessionGenerator<'a> {
    entropy: &'a dyn EntropySource,
    counter: u64,
}

impl<'a> XNonceSessionGenerator<'a> {
    /// Creates a new XNonce session generator with counter initialized to 0.
    ///
    /// # Arguments
    ///
    /// * `entropy` - Entropy source for generating random nonce prefixes
    pub fn new(entropy: &'a dyn EntropySource) -> Self {
        Self {
            entropy,
            counter: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_counter_for_test(&mut self, counter: u64) {
        self.counter = counter;
    }
}

impl<'a> XNonceGenerator for XNonceSessionGenerator<'a> {
    fn fill_current_xnonce(
        &mut self,
        current_xnonce: &mut [u8],
    ) -> Result<(), crate::EntropyError> {
        // First part: random (16 bytes)
        self.entropy.fill_bytes(&mut current_xnonce[..16])?;

        // Second part: counter (8 bytes)
        current_xnonce[16..].copy_from_slice(&self.counter.to_le_bytes());

        // Wrapping add (equivalent to % 2^64)
        self.counter = self.counter.wrapping_add(1);

        Ok(())
    }
}
