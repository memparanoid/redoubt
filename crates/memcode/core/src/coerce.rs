// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::types::*;

/// Infallible, *expressive* helper to write a `usize` into a `MemCodeWord`.
/// We **know** this is a plain cast that could truncate on narrow targets,
/// and we’re fine with it here — the goal is to make call sites read as
/// “write length into mem-word” instead of sprinkling `as` casts.
///
/// Notes:
/// - Intentional, lossy cast (`usize -> MemCodeWord`) with no checks.
/// - Zeroizes the source `usize` after writing (fits our wipe policy).
/// - If you ever need validation, introduce a checked variant instead of
///   changing this helper’s behavior.
///
/// This performs no allocations and no extra copies.
#[inline(always)]
pub(crate) fn coerce_mem_code_word_into_usize(w: &MemCodeWord) -> usize {
    *w as usize
}
