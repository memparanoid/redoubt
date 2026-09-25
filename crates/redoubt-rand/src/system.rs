// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;
use crate::fill::fill_with_random_bytes;
use crate::traits::EntropySource;

/// System-provided cryptographically secure random number generator.
///
/// Uses the OS-level CSPRNG via `getrandom`:
/// - Linux/Android: `getrandom()` syscall
/// - macOS/iOS: `getentropy()`
/// - Windows: `BCryptGenRandom`
/// - WASI: `random_get`
#[derive(Default)]
pub struct SystemEntropySource {}

impl EntropySource for SystemEntropySource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        fill_with_random_bytes(dest)
    }
}
