// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use redoubt_forensics::{QUIET, Report};
use redoubt_zero_core::{FastZeroizable, ZeroizationProbe};

use needles::SECRET;

/// Four kilobytes inline, which is the shape the guard cannot be handed
/// directly.
///
/// `ZeroizingGuard` needs `T: Default`, and `std` implements `Default` for
/// `[T; N]` only up to thirty-two — so the largest inline array it takes is
/// exactly the size at which a swap is still a handful of registers. A caller
/// with a larger key reaches it the way this does, through a type of their own,
/// and the swap that moves it is then a call into the C library with four
/// kilobytes of secret in it.
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

/// The photograph says the secret is there, which is what makes the rest of
/// the section mean anything.
pub(crate) fn is_found(report: &Report, what: &str) {
    println!();
    report.summary(what);
    println!();

    assert!(
        report.found,
        "the sweep does not reach {what}, so every absence below it is the \
         instrument standing where the evidence is: {report}"
    );
}

/// The three things an absence has to survive.
///
/// The whole secret is gone, no piece of it wider than chance is left, and the
/// score did not move. One of the three on its own would pass a process that
/// kept half of it, or kept all of it somewhere the score weighs at nothing.
pub(crate) fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing guarded yet");
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole secret survived {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived {what}, and {QUIET} is what memory has by \
         accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}
