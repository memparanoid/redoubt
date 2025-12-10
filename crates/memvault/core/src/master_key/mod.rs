// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Master key storage

use membuffer::BufferError;
use memzer::ZeroizingGuard;

pub mod buffer;
pub mod consts;
pub mod storage;

use consts::MASTER_KEY_LEN;

pub fn leak_master_key(truncate_at: usize) -> Result<ZeroizingGuard<Vec<u8>>, BufferError> {
    let mut master_key = vec![];
    storage::open(&mut |mk| {
        if truncate_at > MASTER_KEY_LEN {
            return Err(BufferError::callback_error(
                "truncate_at must tle than MASTER_KEY_LEN",
            ));
        }

        master_key.resize_with(truncate_at, || 0u8);
        master_key.copy_from_slice(&mk[..truncate_at]);
        Ok(())
    })?;

    Ok(ZeroizingGuard::new(master_key))
}
