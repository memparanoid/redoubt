// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The portable comparison, for a target the assembly was not written for.

/// Whether the two runs of equal length hold the same bytes.
///
/// Every byte is read whatever the ones before it said, and the answer is
/// folded rather than branched on, so the time this takes says nothing about
/// where the two differ.
///
/// What it cannot promise is where the bytes were while that happened.
/// `black_box` is what stops the optimizer proving the fold away, and what it
/// does is materialize the value and forbid reasoning about it — so the
/// accumulator ends up somewhere real that nothing here empties. At a tag's
/// width the loop also vectorizes, which puts both operands in registers no
/// wipe in this workspace touches. The assembly beside this file is what
/// answers for that; this is what a target without it gets.
pub(crate) fn eq(a: &[u8], b: &[u8]) -> bool {
    let mut acc = 0u8;

    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }

    core::hint::black_box(acc) == 0
}
