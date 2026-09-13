// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Master key storage
use alloc::vec;
use alloc::vec::Vec;

use redoubt_buffer::BufferError;
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

        // Not `copy_from_slice`, which is `core::ptr::copy_nonoverlapping`
        // underneath. A length the compiler cannot see is a call into the C
        // library's `memcpy`, and glibc's moves the bytes through vector
        // registers that nothing afterwards writes over — so the whole key
        // stays in one of them until the process ends. This copy erases the
        // registers it used.
        //
        // SAFETY: `mk` is at least `truncate_at` long, checked above against
        // `MASTER_KEY_LEN`, and `master_key` was created with exactly that
        // length. The two are different allocations, so they cannot overlap.
        unsafe {
            redoubt_mem::copy_nonoverlapping(mk.as_ptr(), master_key.as_mut_ptr(), truncate_at);
        }

        Ok(())
    })?;

    Ok(ZeroizingGuard::from_mut(&mut master_key))
}
