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

use crate::Backend;

/// Whether this target was built with assembly, which is what `Auto` goes to.
///
/// Where it is false the two backends are the same code, and a test that finds
/// them agreeing has proved nothing.
#[cfg(test)]
pub(crate) const HAS_ASM: bool = cfg!(ct_asm);

/// Whether the two runs hold the same bytes, in a time that says nothing about
/// where they differ.
///
/// What every caller outside a test reaches for, and the only one exported.
/// Runs of different length answer false without either being read: that is not
/// a timing question, a tag of the wrong width is a public fact about what
/// arrived and the caller knew it before asking.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq_with_backend(Backend::default(), a, b)
}

/// The same, with the backend named rather than taken as the default has it.
///
/// Not exported: nothing above this crate chooses how a tag is compared, and a
/// construction that could would be choosing for its caller. It is separate so
/// that a test can hold both implementations to the same answer, and so that
/// the one above stays a function real callers use — which a test of it has to
/// exercise, or resolving the default is the one step nothing covers.
pub(crate) fn constant_time_eq_with_backend(backend: Backend, a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    match backend {
        Backend::Rust => rust::eq(a, b),
        Backend::Auto => chosen::eq(a, b),
    }
}
