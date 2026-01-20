// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::cell::Cell;

use crate::error::EntropyError;
use crate::system::SystemEntropySource;
use crate::traits::EntropySource;

/// Configurable behavior for [`MockEntropySource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockEntropySourceBehaviour {
    /// Normal operation (delegates to real entropy source).
    None,
    /// Always fail fill_bytes.
    FailAlways,
    /// Fail fill_bytes on the Nth call (1-indexed: 1 = first call fails).
    FailAtNthFillBytes(usize),
}

/// Mock entropy source for testing.
///
/// Wraps [`SystemEntropySource`] but allows simulating failures via [`MockEntropySourceBehaviour`].
pub struct MockEntropySource {
    inner: SystemEntropySource,
    behaviour: MockEntropySourceBehaviour,
    fill_bytes_count: Cell<usize>,
}

impl MockEntropySource {
    /// Creates a new mock entropy source with the specified behavior.
    pub fn new(behaviour: MockEntropySourceBehaviour) -> Self {
        Self {
            inner: SystemEntropySource {},
            behaviour,
            fill_bytes_count: Cell::new(0),
        }
    }

    /// Changes the mock behavior at runtime.
    pub fn change_behaviour(&mut self, behaviour: MockEntropySourceBehaviour) {
        self.behaviour = behaviour;
    }

    /// Resets the call counter.
    pub fn reset_count(&self) {
        self.fill_bytes_count.set(0);
    }

    /// Returns the current call count.
    pub fn call_count(&self) -> usize {
        self.fill_bytes_count.get()
    }
}

impl EntropySource for MockEntropySource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        let current = self.fill_bytes_count.get();
        self.fill_bytes_count.set(current + 1);

        match self.behaviour {
            MockEntropySourceBehaviour::None => self.inner.fill_bytes(dest),
            MockEntropySourceBehaviour::FailAlways => Err(EntropyError::EntropyNotAvailable),
            MockEntropySourceBehaviour::FailAtNthFillBytes(n) if current + 1 == n => {
                Err(EntropyError::EntropyNotAvailable)
            }
            MockEntropySourceBehaviour::FailAtNthFillBytes(_) => self.inner.fill_bytes(dest),
        }
    }
}
