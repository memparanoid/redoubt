// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod keystream;
pub(crate) mod needles;

use std::vec::Vec;

/// A needle, built from its last byte to its first and never turned around: the
/// forward bytes must not exist in this process.
pub(crate) fn backwards(of: &[u8]) -> Vec<u8> {
    of.iter().rev().copied().collect()
}

/// `from` into somewhere the caller owns, through the copy that erases what it
/// used: a compiler move would leave residue the test caused itself.
pub(crate) fn giving(into: &mut [u8], from: &[u8]) {
    assert_eq!(into.len(), from.len(), "a planting of the wrong width");

    // SAFETY: both are as long as each other, checked above, and a constant
    // and a destination the caller owns are different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len()) };
}
