// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The routine written by hand, at `src/asm/rand_x86_64.S` and
//! `src/asm/rand_aarch64.S`.

use crate::error::EntropyError;

unsafe extern "C" {
    /// `len` random bytes at `dst`, at most `MOST`, and one or zero written to
    /// `*answer`: nothing crosses back in a register.
    fn redoubt_rand_fill(dst: *mut u8, len: usize, answer: *mut u8);
}

/// The most one call asks for: up to this, the kernel returns every byte once
/// its pool is ready.
pub(crate) const MOST: usize = 256;

pub(crate) fn fill(dest: &mut [u8]) -> Result<(), EntropyError> {
    for piece in dest.chunks_mut(MOST) {
        let mut answer = 0_u8;

        // SAFETY: `piece` is writable for its own length, which is at most
        // `MOST`, and `answer` is one byte this frame owns.
        unsafe { redoubt_rand_fill(piece.as_mut_ptr(), piece.len(), &mut answer) };

        if answer != 1 {
            return Err(EntropyError::EntropyNotAvailable);
        }
    }

    Ok(())
}
