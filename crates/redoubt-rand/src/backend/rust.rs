// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The portable fill: the `getrandom` crate.

use crate::error::EntropyError;

pub(crate) fn fill(dest: &mut [u8]) -> Result<(), EntropyError> {
    getrandom::fill(dest).map_err(|_| EntropyError::EntropyNotAvailable)
}
