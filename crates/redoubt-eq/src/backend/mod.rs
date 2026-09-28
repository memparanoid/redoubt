// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The comparison, once in Rust and once by hand.
//!
//! Nothing crosses the boundary by value and nothing is returned. A returned
//! value leaves in a register, and a register carrying the answer out is a
//! register the wipe at the end of an assembly routine cannot touch.
//!
//! `eq_asm` is set by the build script for a target it compiled assembly for,
//! and is named nowhere but the alias below.

pub(crate) mod rust;

#[cfg(eq_asm)]
pub(crate) mod asm;

#[cfg(eq_asm)]
use asm as chosen;

#[cfg(not(eq_asm))]
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
pub(crate) const HAS_ASM: bool = cfg!(eq_asm);

/// Whether `a` and `b` hold the same bytes, in a time that says nothing about
/// where they differ.
///
/// Runs of different length answer false without either being read: a length
/// is public, not a timing question.
pub(crate) fn constant_time_eq(backend: Backend, a: &[u8], b: &[u8]) -> bool {
    match backend {
        Backend::Rust => rust::constant_time_eq(a, b),
        Backend::Auto => chosen::constant_time_eq(a, b),
    }
}
