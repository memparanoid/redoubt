// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a guard leaves behind between taking a value and dropping it.
//!
//! # Why the two shapes are separate tests
//!
//! `ZeroizingGuard::from_mut` is a `mem::swap` between the caller's value and
//! a freshly boxed default, and what that swap moves depends entirely on `T`.
//!
//! A `Vec<u8>` is a pointer, a length and a capacity: the swap moves
//! twenty-four bytes of header and the secret never leaves the heap block it
//! was already in. An inline `[u8; N]` has no header — the swap moves the
//! secret itself, through whatever the compiler picked to move it with.
//!
//! Those are two different questions with the same name on them, and a single
//! test answering both would say which only by accident.
//!
//! # Sizes
//!
//! The array is fixed, so only the vec sweeps. Where a leak appears at one
//! size and not another says whether it came from the copy's own paths or from
//! pressure on the register allocator.
//!
//! # The guard is dropped before the photograph
//!
//! A guard still holding the secret would be found, and would say nothing.

#![cfg(target_os = "linux")]

use redoubt_forensics::{AnyError, Forensics, QUIET, forensics};
use redoubt_zero_core::{FastZeroizable, ZeroizationProbe, ZeroizingGuard, ZeroizingMutGuard};

/// Four kilobytes inline, which is the shape the guard cannot be handed
/// directly.
///
/// `ZeroizingGuard` needs `T: Default`, and `std` implements `Default` for
/// `[T; N]` only up to thirty-two — so the largest inline array it takes is
/// exactly the size at which a swap is still a handful of registers. A caller
/// with a larger key reaches it the way this does, through a type of their own,
/// and the swap that moves it is then a call into the C library with four
/// kilobytes of secret in it.
struct Wide([u8; 4096]);

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

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives where nothing can write and the sweep never reads it
/// as a copy.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// Every size worth asking about: the boundaries of the copy's three paths,
/// and then past anything a register allocator is comfortable with.
const SIZES: [usize; 8] = [32, 64, 128, 512, 1024, 4096, 16384, 65536];

/// The needle, built from its last byte to its first.
fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// The secret over and over, by the copy that erases what it used, so that
/// filling the source is not itself the leak.
fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// Everything a caller must be able to say about what an operation left.
fn leaves_nothing(
    what: &str,
    report_after: &redoubt_forensics::Report,
    before: &redoubt_forensics::Report,
) {
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

    let delta = report_after.against(before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}

// ============================================================================
// The control
// ============================================================================

/// The sweep finds the secret when the secret is plainly there.
///
/// A test of its own, so the copy it plants is in nobody else's memory.
#[test]
fn test_the_sweep_finds_the_secret_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut held = vec![0_u8; SECRET.len()];

    giving(&mut held);
    core::hint::black_box(&held);

    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_in_plain_sight.summary("the secret, held");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep does not reach where a copy lives, so every absence this file \
         reports is the instrument standing where the evidence is: \
         {report_in_plain_sight}",
    );

    drop(core::hint::black_box(held));

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Vec<u8>>
// ============================================================================

/// A heap-backed value, where the swap moves a header and not the bytes.
#[test]
fn test_guarding_a_vec_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing guarded yet");

    for of in SIZES {
        let report_after = forensics!(watch, {
            let mut source = vec![0_u8; of];

            giving(&mut source);

            let guard = ZeroizingGuard::from_mut(&mut source);

            drop(core::hint::black_box(guard));
            drop(core::hint::black_box(source));
        });

        report_after.summary_against(&report_before, &format!("a vec guarded, {of} bytes"));

        leaves_nothing(
            &format!("a vec of {of} bytes"),
            &report_after,
            &report_before,
        );
    }

    println!();

    Ok(())
}

// ============================================================================
// ZeroizingGuard<[u8; 32]>
// ============================================================================

/// An inline value, where the swap moves the secret itself.
///
/// This is the shape that caught `RedoubtArray`: a `swap` of an inline array
/// moves the bytes rather than a pointer to them, and what it moves them
/// through is nobody's to choose.
#[test]
fn test_guarding_an_array_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let report_after = forensics!(watch, {
        let mut source = [0_u8; 32];

        giving(&mut source);

        let guard = ZeroizingGuard::from_mut(&mut source);

        // By reference on purpose: `[u8; 32]` is `Copy`, so a `black_box` of it
        // by value makes one more copy on the stack, and the test would be
        // measuring itself.
        core::hint::black_box(&source);

        drop(core::hint::black_box(guard));
    });

    // Last, and only now: a copy in plain sight. Every zero above is worth
    // what this line is worth, and it has to be planted in *this* process —
    // the control test above is a different one, and proves nothing here.
    let planted = core::hint::black_box(backwards().iter().rev().copied().collect::<Vec<u8>>());
    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_before.summary("nothing guarded yet");
    report_after.summary_against(&report_before, "an array guarded");
    report_in_plain_sight.summary_against(&report_after, "a copy in plain sight");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep reached nowhere in this process, so the zero above means \
         nothing: {report_in_plain_sight}",
    );

    leaves_nothing("an array of 32 bytes", &report_after, &report_before);

    drop(core::hint::black_box(planted));

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Wide>
// ============================================================================

/// The same swap, on four kilobytes the compiler cannot keep in registers.
///
/// This is the one the thirty-two byte test cannot reach: at that size a
/// `mem::swap` is a few loads and stores, and at this one it is a call into
/// the C library with the secret as its argument.
#[test]
fn test_guarding_a_wide_value_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let report_after = forensics!(watch, {
        let mut source = Wide::default();

        giving(&mut source.0);

        let guard = ZeroizingGuard::from_mut(&mut source);

        core::hint::black_box(&source);

        drop(core::hint::black_box(guard));
    });

    let planted = core::hint::black_box(backwards().iter().rev().copied().collect::<Vec<u8>>());
    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_before.summary("nothing guarded yet");
    report_after.summary_against(&report_before, "four kilobytes guarded");
    report_in_plain_sight.summary_against(&report_after, "a copy in plain sight");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep reached nowhere in this process, so the zero above means \
         nothing: {report_in_plain_sight}",
    );

    leaves_nothing("four kilobytes", &report_after, &report_before);

    drop(core::hint::black_box(planted));

    Ok(())
}

/// The sweep finds four kilobytes when four kilobytes are there.
///
/// The control beside the other tests plants thirty-two bytes in a `Vec` on
/// the heap, which says the sweep reaches the heap and nothing about whether
/// it reaches what a swap of an inline value leaves. This plants the shape
/// that is actually being measured: a `Wide` taken by a guard that is then
/// forgotten, so nothing zeroizes it.
///
/// Without this, the zero next door is a zero nobody has earned.
#[test]
fn test_the_sweep_finds_a_wide_value_a_guard_did_not_zeroize() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    let guard = ZeroizingGuard::from_mut(&mut source);

    // Forgotten on purpose: `Drop` is what zeroizes, so this is the same
    // operation as the test beside it with the cleaning taken away.
    core::mem::forget(guard);

    let report_after = watch.snapshot()?;

    println!();
    report_before.summary("nothing guarded yet");
    report_after.summary_against(&report_before, "four kilobytes, not zeroized");
    println!();

    assert!(
        report_after.found,
        "the sweep cannot see four kilobytes of an inline value even when they \
         are plainly there, so the absence its sibling reports is the instrument \
         and not the code: {report_after}",
    );

    Ok(())
}

// ============================================================================
// ZeroizingMutGuard
// ============================================================================

/// The same two shapes, for the guard that borrows instead of taking.
///
/// This one holds a `&mut T` and never moves the value at all: the secret
/// stays in the caller's own variable and is zeroized there when the guard
/// drops. So there is nothing for a swap to leave anywhere, and what this
/// measures is that claim rather than a hope.
///
/// It is worth pinning even so. The difference between the two guards is one
/// word in a struct field, and a future `from` that took `T` by value would
/// read almost the same and leak exactly like the other one did.
#[test]
fn test_borrowing_a_vec_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing guarded yet");

    for of in SIZES {
        let report_after = forensics!(watch, {
            let mut source = vec![0_u8; of];

            giving(&mut source);

            let guard = ZeroizingMutGuard::from(&mut source);

            drop(core::hint::black_box(guard));
            drop(core::hint::black_box(source));
        });

        report_after.summary_against(&report_before, &format!("a vec borrowed, {of} bytes"));

        leaves_nothing(
            &format!("a vec of {of} bytes"),
            &report_after,
            &report_before,
        );
    }

    println!();

    Ok(())
}

/// Four kilobytes inline, borrowed rather than taken.
///
/// The shape that caught the other guard: there, the swap moved the value and
/// left sixteen bytes of it in a vector register on `aarch64`. Here nothing is
/// moved, so there should be nothing to find — and the control below is what
/// makes that zero worth reading.
#[test]
fn test_borrowing_a_wide_value_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let report_after = forensics!(watch, {
        let mut source = Wide::default();

        giving(&mut source.0);

        let guard = ZeroizingMutGuard::from(&mut source);

        drop(core::hint::black_box(guard));

        core::hint::black_box(&source);
    });

    let planted = core::hint::black_box(backwards().iter().rev().copied().collect::<Vec<u8>>());
    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_before.summary("nothing guarded yet");
    report_after.summary_against(&report_before, "four kilobytes borrowed");
    report_in_plain_sight.summary_against(&report_after, "a copy in plain sight");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep reached nowhere in this process, so the zero above means \
         nothing: {report_in_plain_sight}",
    );

    leaves_nothing("four kilobytes", &report_after, &report_before);

    drop(core::hint::black_box(planted));

    Ok(())
}

/// The sweep finds four kilobytes a borrowing guard did not zeroize.
///
/// Forgetting this guard leaves the secret where it always was — in the
/// caller's variable, never wiped. If the sweep could not see that, it could
/// not see a leak in the test above either.
#[test]
fn test_the_sweep_finds_a_wide_value_a_borrowing_guard_did_not_zeroize() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    let guard = ZeroizingMutGuard::from(&mut source);

    // Forgotten on purpose: `Drop` is what zeroizes, so this is the same
    // operation as the test beside it with the cleaning taken away.
    core::mem::forget(guard);

    let report_after = watch.snapshot()?;

    println!();
    report_before.summary("nothing guarded yet");
    report_after.summary_against(&report_before, "four kilobytes, not zeroized");
    println!();

    assert!(
        report_after.found,
        "the sweep cannot see four kilobytes of a borrowed value even when they \
         are plainly there, so the absence its sibling reports is the instrument \
         and not the code: {report_after}",
    );

    core::hint::black_box(&source);

    Ok(())
}
