// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;
use crate::session::XNonceSessionGenerator;
use crate::traits::{EntropySource, XNonceGenerator};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockXNonceGeneratorBehaviour {
    None,
    FailAtFillBytes,
}

pub struct MockXNonceSessionGenerator<'a> {
    inner: XNonceSessionGenerator<'a>,
    behaviour: MockXNonceGeneratorBehaviour,
}

impl<'a> MockXNonceSessionGenerator<'a> {
    pub fn new(entropy: &'a dyn EntropySource, behaviour: MockXNonceGeneratorBehaviour) -> Self {
        Self {
            inner: XNonceSessionGenerator::new(entropy),
            behaviour,
        }
    }

    pub fn change_behaviour(&mut self, behaviour: MockXNonceGeneratorBehaviour) {
        self.behaviour = behaviour;
    }
}

impl<'a> XNonceGenerator for MockXNonceSessionGenerator<'a> {
    fn fill_current_xnonce(&mut self, current_xnonce: &mut [u8]) -> Result<(), EntropyError> {
        match self.behaviour {
            MockXNonceGeneratorBehaviour::None => self.inner.fill_current_xnonce(current_xnonce),
            MockXNonceGeneratorBehaviour::FailAtFillBytes => Err(EntropyError::EntropyNotAvailable),
        }
    }
}
