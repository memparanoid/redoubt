// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_asm::Backend;

use crate::backend;
use crate::error::EntropyError;

/// Fills a buffer with cryptographically secure random bytes.
///
/// On Linux, x86-64 and AArch64, the kernel writes them straight into `dest`,
/// asked by a routine that leaves none of them in a register. Elsewhere they
/// come from the `getrandom` crate.
///
/// # Example
///
/// ```rust
/// use redoubt_rand::fill_with_random_bytes;
///
/// let mut key = [0u8; 32];
/// fill_with_random_bytes(&mut key).expect("Failed to generate random bytes");
/// ```
pub fn fill_with_random_bytes(dest: &mut [u8]) -> Result<(), EntropyError> {
    backend::fill(Backend::default(), dest)
}
