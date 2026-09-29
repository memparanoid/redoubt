// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use crate::{FastZeroizable, ZeroizationProbe};

use needles::SECRET;

/// Four kilobytes inline. `std` implements `Default` for arrays only up to
/// thirty-two elements, so a larger key reaches `ZeroizingGuard` through a type
/// of its own, and the swap that moves it is a call into the C library.
pub(crate) struct Wide(pub(crate) [u8; 4096]);

impl Default for Wide {
    fn default() -> Self {
        Self([0_u8; 4096])
    }
}

impl FastZeroizable for Wide {
    fn fast_zeroize(&mut self) {
        self.0.fast_zeroize();
    }
}

impl ZeroizationProbe for Wide {
    fn is_zeroized(&self) -> bool {
        self.0.is_zeroized()
    }
}

/// The secret over and over, by the copy that erases what it used, so that
/// filling the source is not itself the leak.
pub(crate) fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// Takes the guard and lets it go, which runs its drop somewhere this test
/// cannot see.
///
/// Not inlined: a move within one function is one the optimiser may fold away,
/// and a measurement of what a move leaves has to be sure a move happened.
#[inline(never)]
pub(crate) fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the guard the same way and never lets it go.
#[inline(never)]
pub(crate) fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}
