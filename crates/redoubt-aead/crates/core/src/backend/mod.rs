// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The comparison, once in Rust and once by hand.
//!
//! Every construction above this crate ends by comparing a tag it computed
//! against one that arrived, so the comparison is here rather than in each of
//! them — two copies of the same fold are two copies that agree today.
//!
//! Nothing crosses the boundary by value and nothing is returned. A returned
//! value leaves in a register, and a register carrying the answer out is a
//! register the wipe at the end of an assembly routine cannot touch.
//!
//! `ct_asm` is set by the build script for a target it compiled assembly for,
//! and is named nowhere but the alias below.

pub(crate) mod rust;

#[cfg(ct_asm)]
pub(crate) mod asm;

#[cfg(ct_asm)]
use asm as chosen;

#[cfg(not(ct_asm))]
use rust as chosen;

use redoubt_asm::Backend;

/// Whether this target was built with assembly, which is what `Auto` goes to.
///
/// Where it is false the two backends are the same code, and a test that finds
/// them agreeing has proved nothing.
#[cfg(all(
    test,
    not(target_os = "windows"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) const HAS_ASM: bool = cfg!(ct_asm);

/// Whether `a` and `b` hold the same bytes, in a time that says nothing about
/// where they differ.
///
/// # Safety
///
/// `a` and `b` of the same length.
pub(crate) unsafe fn constant_time_eq(backend: Backend, a: &[u8], b: &[u8]) -> bool {
    match backend {
        Backend::Rust => rust::constant_time_eq(a, b),
        // SAFETY: the caller's, verbatim.
        Backend::Auto => unsafe { chosen::constant_time_eq(a, b) },
    }
}
