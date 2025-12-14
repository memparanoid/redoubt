// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Master key storage
use alloc::vec;
use alloc::vec::Vec;

use membuffer::BufferError;
use redoubt_zero::ZeroizingGuard;

pub mod buffer;
pub mod consts;
pub mod storage;

use consts::MASTER_KEY_LEN;

pub fn leak_master_key(truncate_at: usize) -> Result<ZeroizingGuard<Vec<u8>>, BufferError> {
    let mut master_key = vec![0u8; truncate_at];

    storage::open(&mut |mk| {
        // NOTE: Validation is inside the closure (not before vec allocation) for test coverage.
        // The `?` operator needs to be covered, and having it only inside the closure ensures
        // it can be tested. In practice, truncate_at is always 16 or 32 bytes (never fails).
        if truncate_at > MASTER_KEY_LEN {
            return Err(BufferError::callback_error(
                "truncate_at must be less than MASTER_KEY_LEN",
            ));
        }

        master_key.copy_from_slice(&mk[..truncate_at]);
        Ok(())
    })?;

    Ok(ZeroizingGuard::new(master_key))
}
