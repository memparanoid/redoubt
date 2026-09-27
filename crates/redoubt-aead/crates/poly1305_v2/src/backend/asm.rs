// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The arithmetic by hand, where a target has it.

use redoubt_aead_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE};

use crate::consts::{ACC_WORDS, R_WORDS};

unsafe extern "C" {
    fn redoubt_poly1305_v2_init(r: *mut u64, s: *mut u8, key: *const u8);
    fn redoubt_poly1305_v2_update(
        acc: *mut u64,
        r: *const u64,
        block: *mut u8,
        filled: *mut usize,
        said: *const u8,
        said_len: usize,
    );
}

pub(crate) fn init(r: &mut [u64; R_WORDS], s: &mut [u8; BLOCK_SIZE], key: &[u8; KEY_SIZE]) {
    // SAFETY: the three arrays are the widths the routine reads and writes,
    // and `r` and `s` are distinct fields of one struct, so neither overlaps
    // the other nor the key the caller lent.
    unsafe { redoubt_poly1305_v2_init(r.as_mut_ptr(), s.as_mut_ptr(), key.as_ptr()) };
}

pub(crate) fn update(
    acc: &mut [u64; ACC_WORDS],
    r: &[u64; R_WORDS],
    block: &mut [u8; BLOCK_SIZE],
    filled: &mut usize,
    said: &[u8],
) {
    // SAFETY: every pointer is to storage of the width the routine reads or
    // writes, `said` is as long as the length beside it, and `filled` arrives
    // no greater than the block it indexes.
    unsafe {
        redoubt_poly1305_v2_update(
            acc.as_mut_ptr(),
            r.as_ptr(),
            block.as_mut_ptr(),
            filled,
            said.as_ptr(),
            said.len(),
        );
    }
}
