// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::MemDecodeError;
use crate::traits::*;
use crate::types::*;

impl<const N: usize> MemDrainDecode for [MemCodeUnit; N] {
    fn drain_from(&mut self, words: &mut [MemCodeWord]) -> Result<(), MemDecodeError> {
        self.as_mut_slice().drain_from(words)
    }
}
