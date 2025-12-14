// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;
use crate::system::SystemEntropySource;
use crate::traits::EntropySource;

/// Configurable behavior for [`MockEntropySource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockEntropySourceBehaviour {
    /// Normal operation (delegates to real entropy source).
    None,
    /// Simulates entropy source failure.
    FailAtFillBytes,
}

/// Mock entropy source for testing.
///
/// Wraps [`SystemEntropySource`] but allows simulating failures via [`MockEntropySourceBehaviour`].
pub struct MockEntropySource {
    inner: SystemEntropySource,
    behaviour: MockEntropySourceBehaviour,
}

impl MockEntropySource {
    /// Creates a new mock entropy source with the specified behavior.
    pub fn new(behaviour: MockEntropySourceBehaviour) -> Self {
        Self {
            inner: SystemEntropySource {},
            behaviour,
        }
    }

    /// Changes the mock behavior at runtime.
    pub fn change_behaviour(&mut self, behaviour: MockEntropySourceBehaviour) {
        self.behaviour = behaviour;
    }
}

impl EntropySource for MockEntropySource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        match self.behaviour {
            MockEntropySourceBehaviour::None => self.inner.fill_bytes(dest),
            MockEntropySourceBehaviour::FailAtFillBytes => Err(EntropyError::EntropyNotAvailable),
        }
    }
}
