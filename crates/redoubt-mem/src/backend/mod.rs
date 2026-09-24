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
//! `mem_asm` is set by the build script for a target it compiled assembly for,
//! and it is named nowhere but the alias below: `Auto` is whatever was chosen
//! for this target.

pub(crate) mod rust;

#[cfg(mem_asm)]
pub(crate) mod asm;

#[cfg(mem_asm)]
use asm as chosen;

#[cfg(not(mem_asm))]
use rust as chosen;

use redoubt_asm::Backend;

/// Whether this target was built with assembly.
#[cfg(test)]
pub(crate) const HAS_ASM: bool = cfg!(mem_asm);

/// `bytes` from `src` to `dst`.
///
/// # Safety
///
/// `src` readable and `dst` writable for `bytes`, and the two ranges disjoint.
pub(crate) unsafe fn copy_nonoverlapping(
    backend: Backend,
    src: *const u8,
    dst: *mut u8,
    bytes: usize,
) {
    match backend {
        // SAFETY: the caller's, verbatim.
        Backend::Rust => unsafe { rust::copy_nonoverlapping(src, dst, bytes) },
        // SAFETY: the caller's, verbatim.
        Backend::Auto => unsafe { chosen::copy_nonoverlapping(src, dst, bytes) },
    }
}

/// `bytes` exchanged between `a` and `b`.
///
/// # Safety
///
/// `a` and `b` readable and writable for `bytes`, and the two ranges disjoint.
pub(crate) unsafe fn swap_nonoverlapping(backend: Backend, a: *mut u8, b: *mut u8, bytes: usize) {
    match backend {
        // SAFETY: the caller's, verbatim.
        Backend::Rust => unsafe { rust::swap_nonoverlapping(a, b, bytes) },
        // SAFETY: the caller's, verbatim.
        Backend::Auto => unsafe { chosen::swap_nonoverlapping(a, b, bytes) },
    }
}

/// Whether `bytes` spell UTF-8.
pub(crate) fn is_utf8(backend: Backend, bytes: &[u8]) -> bool {
    match backend {
        Backend::Rust => rust::is_utf8(bytes),
        Backend::Auto => chosen::is_utf8(bytes),
    }
}
