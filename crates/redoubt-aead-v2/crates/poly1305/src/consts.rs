// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! How the hundred and thirty bits are carried.
//!
//! Not beside the widths, which are a contract anybody can read: these two are
//! a decision about arithmetic that nothing outside this crate can act on, and
//! the assembly is free to reach the same answer in another radix.

/// Limbs the accumulator and `r` are carried in.
///
/// One hundred and thirty bits over five limbs of twenty-six, so that the
/// product of two limbs is fifty-two bits and the five of them landing on one
/// power still fit in a `u64` with room left to carry. Radix 2^32 would need a
/// widening multiply into `u128`, which is a call on the targets that have no
/// instruction for one — and this is the backend those targets run.
pub(crate) const LIMBS: usize = 5;

/// What a limb is taken modulo, less one: 2^26 - 1.
pub(crate) const LIMB_MASK: u64 = 0x3ff_ffff;
