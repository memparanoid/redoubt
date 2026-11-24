// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use needles::NEEDLE;

/// Writes the needle over and over into `into`, through the copy that erases
/// what it used: a compiler move would leave residue the test caused itself.
pub(crate) fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(NEEDLE.len()) {
        // SAFETY: `one` is at most as long as the needle, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(NEEDLE.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// Takes the value and lets it go, which runs its drop somewhere this test
/// cannot see.
///
/// Not inlined: a move within one function is one the optimiser may fold away,
/// and a measurement of what a move leaves has to be sure a move happened.
#[inline(never)]
pub(crate) fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the value the same way and never lets it go.
#[inline(never)]
pub(crate) fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}
