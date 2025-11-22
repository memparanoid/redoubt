// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use getrandom::Error as GetRandomError;

use crate::{EntropySource, error::EntropyError};

/// System-provided cryptographically secure random number generator.
///
/// Uses the OS-level CSPRNG via `getrandom`:
/// - Linux/Android: `getrandom()` syscall
/// - macOS/iOS: `getentropy()`
/// - Windows: `BCryptGenRandom`
/// - WASI: `random_get`
pub struct SystemEntropySource {}

impl SystemEntropySource {
    pub(crate) fn fill_bytes_with(
        fill_fn: &dyn Fn(&mut [u8]) -> Result<(), GetRandomError>,
        dest: &mut [u8],
    ) -> Result<(), EntropyError> {
        fill_fn(dest).map_err(|_| EntropyError::EntropyNotAvailable)
    }
}

impl EntropySource for SystemEntropySource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        Self::fill_bytes_with(&getrandom::fill, dest)
    }
}
