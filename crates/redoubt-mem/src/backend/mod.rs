// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The copy, the swap and the check, once from the standard library and once
//! by hand.
//!
//! The two answer the same, and the tests hold them to it on every
//! architecture the assembly was written for. What one of them has and the
//! other cannot is a list of the registers it used, every one emptied before
//! it returns.
//!
//! `mem_asm` is set by the build script for a target it compiled assembly for.
//! Nothing here is written in terms of that beyond what `Auto` resolves to:
//! the choice is a value a caller passes, so the same test runs on a target
//! with assembly and on one without.

pub(crate) mod rust;

#[cfg(mem_asm)]
pub(crate) mod asm;

use redoubt_asm::Backend;

/// Whether this target was built with assembly, which is what `Auto` goes to.
#[cfg(test)]
pub(crate) const HAS_ASM: bool = cfg!(mem_asm);

/// `bytes` from `src` to `dst`.
///
/// # Safety
///
/// `src` readable and `dst` writable for `bytes`, and the two ranges disjoint.
pub(crate) unsafe fn copy_bytes(backend: Backend, src: *const u8, dst: *mut u8, bytes: usize) {
    match backend {
        // SAFETY: the caller's, verbatim.
        Backend::Rust => unsafe { rust::copy_bytes(src, dst, bytes) },
        // SAFETY: the caller's, verbatim.
        Backend::Auto => unsafe { auto_copy_bytes(src, dst, bytes) },
    }
}

/// What `Auto` is on a target the build script compiled assembly for.
///
/// # Safety
///
/// As [`copy_bytes`].
#[cfg(mem_asm)]
unsafe fn auto_copy_bytes(src: *const u8, dst: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { asm::copy_bytes(src, dst, bytes) }
}

/// What `Auto` is anywhere else.
///
/// # Safety
///
/// As [`copy_bytes`].
#[cfg(not(mem_asm))]
unsafe fn auto_copy_bytes(src: *const u8, dst: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { rust::copy_bytes(src, dst, bytes) }
}

/// `bytes` exchanged between `a` and `b`.
///
/// # Safety
///
/// `a` and `b` readable and writable for `bytes`, and the two ranges disjoint.
pub(crate) unsafe fn swap_bytes(backend: Backend, a: *mut u8, b: *mut u8, bytes: usize) {
    match backend {
        // SAFETY: the caller's, verbatim.
        Backend::Rust => unsafe { rust::swap_bytes(a, b, bytes) },
        // SAFETY: the caller's, verbatim.
        Backend::Auto => unsafe { auto_swap_bytes(a, b, bytes) },
    }
}

/// What `Auto` is on a target the build script compiled assembly for.
///
/// # Safety
///
/// As [`swap_bytes`].
#[cfg(mem_asm)]
unsafe fn auto_swap_bytes(a: *mut u8, b: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { asm::swap_bytes(a, b, bytes) }
}

/// What `Auto` is anywhere else.
///
/// # Safety
///
/// As [`swap_bytes`].
#[cfg(not(mem_asm))]
unsafe fn auto_swap_bytes(a: *mut u8, b: *mut u8, bytes: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { rust::swap_bytes(a, b, bytes) }
}

/// Whether `bytes` spell UTF-8.
pub(crate) fn is_utf8(backend: Backend, bytes: &[u8]) -> bool {
    match backend {
        Backend::Rust => rust::is_utf8(bytes),
        Backend::Auto => auto_is_utf8(bytes),
    }
}

/// What `Auto` is on a target the build script compiled assembly for.
#[cfg(mem_asm)]
fn auto_is_utf8(bytes: &[u8]) -> bool {
    asm::is_utf8(bytes)
}

/// What `Auto` is anywhere else.
#[cfg(not(mem_asm))]
fn auto_is_utf8(bytes: &[u8]) -> bool {
    rust::is_utf8(bytes)
}
