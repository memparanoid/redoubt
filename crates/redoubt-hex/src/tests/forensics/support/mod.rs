// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

/// A needle built from its last byte to its first and never turned around: the
/// forward bytes must not exist in this process.
pub(crate) fn backwards(of: &[u8]) -> Vec<u8> {
    of.iter().rev().copied().collect()
}

/// `of` in a heap block, through the probed copy: a compiler copy would leave
/// residue the test caused itself.
pub(crate) fn hold(of: &[u8]) -> Vec<u8> {
    let mut held = vec![0_u8; of.len()];

    // SAFETY: `held` was just allocated, so it overlaps nothing, and both are
    // `of.len()` bytes.
    unsafe { redoubt_mem::copy_nonoverlapping(of.as_ptr(), held.as_mut_ptr(), of.len()) };

    held
}

pub(crate) fn wipe(held: &mut [u8]) {
    // SAFETY: `held` is a live slice of `held.len()` bytes, borrowed exclusively.
    unsafe { redoubt_mem::zeroize(held.as_mut_ptr(), held.len()) };
}
