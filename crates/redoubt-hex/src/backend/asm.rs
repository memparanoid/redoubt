// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The routines written by hand, at `src/asm/hex_x86_64.S` and
//! `src/asm/hex_aarch64.S`.

unsafe extern "C" {
    /// `len` bytes at `src` as `2 * len` lowercase digits at `dst`.
    fn redoubt_hex_bytes_to_hex(src: *const u8, len: usize, dst: *mut u8);

    /// `len` digits at `src` as `len / 2` bytes at `dst`, and whether every one
    /// was a hex digit written to `*answer` as one or zero: nothing crosses
    /// back in a register.
    fn redoubt_hex_hex_to_bytes(src: *const u8, len: usize, dst: *mut u8, answer: *mut u8);
}

/// What `rust::bytes_to_hex` does, in the assembly for this target.
///
/// # Safety
///
/// `dst` twice as long as `src`.
pub(crate) unsafe fn bytes_to_hex(src: &[u8], dst: &mut [u8]) {
    // SAFETY: the routine reads `src` for its own length and writes twice that
    // into `dst`, which the caller made that long.
    unsafe { redoubt_hex_bytes_to_hex(src.as_ptr(), src.len(), dst.as_mut_ptr()) };
}

/// What `rust::hex_to_bytes` does, in the assembly for this target.
///
/// # Safety
///
/// `src` of even length, and `dst` half as long.
pub(crate) unsafe fn hex_to_bytes(src: &[u8], dst: &mut [u8]) -> bool {
    let mut answer = 0_u8;

    // SAFETY: the routine reads `src` for its own length and writes half that
    // into `dst`, which the caller made that long; `answer` is one byte this
    // frame owns.
    unsafe {
        redoubt_hex_hex_to_bytes(src.as_ptr(), src.len(), dst.as_mut_ptr(), &mut answer);
    }

    answer == 1
}
