// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The comparison by hand, on a target the build script compiled it for.

unsafe extern "C" {
    fn redoubt_eq_constant_time_eq(a: *const u8, b: *const u8, len: usize, out: *mut u8);
}

/// Whether `a` and `b` hold the same bytes; false for runs of different length,
/// neither of them read.
///
/// The answer arrives through a byte the caller owns rather than in a register,
/// so the wipe at the end of the routine reaches everything it touched. What it
/// writes there is one or zero and never the fold, which is the exclusive-or of
/// the two runs and of no use to a caller that is not attacking one of them.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut same = 0u8;

    // SAFETY: both pointers are to runs of `a.len()` readable bytes, the
    // lengths having just been found equal, and `same` is one writable byte
    // that neither of them overlaps.
    unsafe { redoubt_eq_constant_time_eq(a.as_ptr(), b.as_ptr(), a.len(), &raw mut same) };

    same == 1
}
