// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! How the hundred and thirty bits are carried: in words of sixty-four, whole.

/// Words `r` is held in: its hundred and twenty-eight clamped bits, as they are.
pub(crate) const R_WORDS: usize = 2;

/// Words the accumulator is held in: two whole, and a third for the few bits
/// above 2^128 that stand between one reduction and the next.
pub(crate) const ACC_WORDS: usize = 3;
