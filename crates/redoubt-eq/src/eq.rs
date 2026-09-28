// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Two runs compared in a time that says nothing about where they differ.

use redoubt_asm::Backend;

use crate::backend;

/// Whether `a` and `b` hold the same bytes, in a time that says nothing about
/// where they differ.
///
/// Runs of different length answer false without either being read: a length
/// is public, not a timing question.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq_using(Backend::default(), a, b)
}

/// [`constant_time_eq`], through the backend named.
pub(crate) fn constant_time_eq_using(backend: Backend, a: &[u8], b: &[u8]) -> bool {
    backend::constant_time_eq(backend, a, b)
}
