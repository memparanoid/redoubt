// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;

pub trait EntropySource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError>;
}

pub trait XNonceGenerator {
    fn fill_current_xnonce(&mut self, current_xnonce: &mut [u8]) -> Result<(), EntropyError>;
}
