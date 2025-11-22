// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;
use crate::system::SystemEntropySource;
use crate::traits::EntropySource;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockEntropySourceBehaviour {
    None,
    FailAtFillBytes,
}

pub struct MockEntropySource {
    inner: SystemEntropySource,
    behaviour: MockEntropySourceBehaviour,
}

impl MockEntropySource {
    pub fn new(behaviour: MockEntropySourceBehaviour) -> Self {
        Self {
            inner: SystemEntropySource {},
            behaviour,
        }
    }

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
