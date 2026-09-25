// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! SHA-256 on its own, for a crate above that needs a digest in its tests.

use redoubt_asm::Backend;

use crate::backend::sha256_hash;
use crate::consts::HASH_SIZE;

/// The SHA-256 digest of `data`, into `out`.
pub fn sha256(data: &[u8], out: &mut [u8; HASH_SIZE]) {
    sha256_hash(Backend::default(), data, out);
}
