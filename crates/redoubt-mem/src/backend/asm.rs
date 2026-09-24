// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The routines written by hand, at `src/asm/mem_x86_64.S` and
//! `src/asm/mem_aarch64.S`.

unsafe extern "C" {
    /// `bytes` from `src` to `dst`, the two ranges disjoint.
    fn redoubt_mem_copy_nonoverlapping(src: *const u8, dst: *mut u8, bytes: usize);

    /// `bytes` exchanged between `a` and `b`, the two ranges disjoint.
    fn redoubt_mem_swap_nonoverlapping(a: *mut u8, b: *mut u8, bytes: usize);

    /// Whether `len` bytes at `bytes` spell UTF-8, written to `*answer` as one
    /// or zero: nothing crosses back in a register.
    fn redoubt_mem_is_utf8(bytes: *const u8, len: usize, answer: *mut u8);
}

/// What `rust::copy_nonoverlapping` does, in the assembly for this target.
///
/// # Safety
///
/// `src` readable and `dst` writable for `bytes`, and the two ranges disjoint.
pub(crate) unsafe fn copy_nonoverlapping(src: *const u8, dst: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { redoubt_mem_copy_nonoverlapping(src, dst, bytes) };
}

/// What `rust::swap_nonoverlapping` does, in the assembly for this target.
///
/// # Safety
///
/// `a` and `b` readable and writable for `bytes`, and the two ranges disjoint.
pub(crate) unsafe fn swap_nonoverlapping(a: *mut u8, b: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { redoubt_mem_swap_nonoverlapping(a, b, bytes) };
}

/// What `rust::is_utf8` does, in the assembly for this target.
pub(crate) fn is_utf8(bytes: &[u8]) -> bool {
    let mut answer = 0_u8;

    // SAFETY: the slice is readable for its own length, which the routine does
    // not read past, and `answer` is one byte this frame owns.
    unsafe { redoubt_mem_is_utf8(bytes.as_ptr(), bytes.len(), &mut answer) };

    answer == 1
}
