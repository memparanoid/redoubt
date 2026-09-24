// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The standard library's copy, swap and check: the same answers, and no
//! promise about the registers they went through.

/// `bytes` from `src` to `dst`.
///
/// # Safety
///
/// `src` readable and `dst` writable for `bytes`, and the two ranges disjoint.
pub(crate) unsafe fn copy_bytes(src: *const u8, dst: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, bytes) };
}

/// `bytes` exchanged between `a` and `b`.
///
/// # Safety
///
/// `a` and `b` readable and writable for `bytes`, and the two ranges disjoint.
pub(crate) unsafe fn swap_bytes(a: *mut u8, b: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { core::ptr::swap_nonoverlapping(a, b, bytes) };
}

/// Whether `bytes` spell UTF-8.
pub(crate) fn is_utf8(bytes: &[u8]) -> bool {
    core::str::from_utf8(bytes).is_ok()
}
