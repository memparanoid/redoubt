// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{EntropySource, XNonceGenerator};

pub struct XNonceSessionGenerator<'a> {
    entropy: &'a dyn EntropySource,
    counter: u64,
}

impl<'a> XNonceSessionGenerator<'a> {
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
