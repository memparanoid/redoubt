// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a guard leaves behind between taking a value and dropping it.
//!
//! # Why each `T` is its own set of sections
//!
//! `ZeroizingGuard::from_mut` is a `mem::swap` between the caller's value and a
//! freshly boxed default, and what that swap moves depends entirely on `T`.
//!
//! A `Vec<u8>` is a pointer, a length and a capacity: the swap moves
//! twenty-four bytes of header and the secret never leaves the heap block it
//! was already in. An inline `[u8; 32]` has no header — the swap moves the
//! secret itself, through whatever the compiler picked to move it with. Four
//! kilobytes inline is a third question again: at that size the move is a call
//! into the C library with the secret as its argument.
//!
//! Those are three different questions with one name on them, and a single test
//! answering all three would say which only by accident.
//!
//! # And why the borrowing guard is measured at all
//!
//! `ZeroizingMutGuard` holds a `&mut T` and never moves the value: the secret
//! stays in the caller's own variable and is zeroized there. So there should be
//! nothing for a move to leave anywhere.
//!
//! It is worth pinning even so. The difference between the two guards is one
//! word in a struct field, and a future `from` that took `T` by value would
//! read almost the same and leak exactly like the other one did.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place the secret could be. `nextest`, not `cargo test`.

#![cfg(target_os = "linux")]

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, elenchos};
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
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// The needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
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

/// Takes the guard and lets it go, which runs its drop somewhere this test
/// cannot see.
///
/// Not inlined: a move within one function is one the optimiser may fold away,
/// and a measurement of what a move leaves has to be sure a move happened.
#[inline(never)]
fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the guard the same way and never lets it go.
#[inline(never)]
fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}

/// The photograph says the secret is there, which is what makes the rest of
/// the section mean anything.
fn is_found(report: &Report, what: &str) {
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
fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
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

// ============================================================================
// ZeroizingGuard<Vec<u8>>::from_mut
// ============================================================================

/// What the guard took is found while the guard holds it.
#[test]
fn test_a_guarded_vec_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        capture!();

        core::mem::forget(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec guarded, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// Taking a vec of one size, and letting the guard go.
macro_rules! a_guarded_vec {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            elenchos!({
                let guard = ZeroizingGuard::from_mut(&mut source);

                capture!();

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the swap left, and then the
                // absence below is about that call and not about the swap.
                drop(guard);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes guarded", $of),
            );

            Ok(())
        }
    };
}

a_guarded_vec!(test_guarding_a_vec_of_32_leaves_nothing, 32);
a_guarded_vec!(test_guarding_a_vec_of_64_leaves_nothing, 64);
a_guarded_vec!(test_guarding_a_vec_of_128_leaves_nothing, 128);
a_guarded_vec!(test_guarding_a_vec_of_512_leaves_nothing, 512);
a_guarded_vec!(test_guarding_a_vec_of_1024_leaves_nothing, 1024);
a_guarded_vec!(test_guarding_a_vec_of_4096_leaves_nothing, 4096);
a_guarded_vec!(test_guarding_a_vec_of_16384_leaves_nothing, 16384);
a_guarded_vec!(test_guarding_a_vec_of_65536_leaves_nothing, 65536);

// ============================================================================
// ZeroizingGuard<Vec<u8>>: ownership
// ============================================================================

/// A guarded vec given away leaves nothing where it was.
#[test]
fn test_a_guarded_vec_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: before the capture, because this is the operation. What
        // the section measures is whether the move itself leaves a copy in the
        // registers or the stack it used.
        let_go(guard);

        capture!();
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded vec given away");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Vec<u8>>::drop
// ============================================================================

/// Dropping the guard leaves nothing.
#[test]
fn test_dropping_a_guarded_vec_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: before the capture, because this is the operation. What
        // the section measures is what the drop itself leaves in the registers
        // or the stack it used.
        drop(guard);

        capture!();
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded vec dropped");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<[u8; 32]>::from_mut
// ============================================================================

/// What the guard took is found while the guard holds it.
///
/// The shape that caught `RedoubtArray`: a swap of an inline array moves the
/// bytes rather than a pointer to them, and what it moves them through is
/// nobody's to choose.
#[test]
fn test_a_guarded_array_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        capture!();

        core::mem::forget(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an array guarded, and kept");

    // By reference on purpose: `[u8; 32]` is `Copy`, so a `black_box` of it by
    // value makes one more copy on the stack, and the test would be measuring
    // itself.
    core::hint::black_box(&source);

    Ok(())
}

/// Taking an array leaves nothing once the guard is let go.
#[test]
fn test_guarding_an_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        capture!();

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the swap left, and then the absence
        // below is about that call and not about the swap.
        drop(guard);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array guarded");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<[u8; 32]>: ownership
// ============================================================================

/// A guarded array given away leaves nothing where it was.
#[test]
fn test_a_guarded_array_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: before the capture, because this is the operation.
        let_go(guard);

        capture!();
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "a guarded array given away",
    );

    Ok(())
}

// ============================================================================
// ZeroizingGuard<[u8; 32]>::drop
// ============================================================================

/// Dropping the guard leaves nothing.
#[test]
fn test_dropping_a_guarded_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: before the capture, because this is the operation.
        drop(guard);

        capture!();
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a guarded array dropped");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Wide>::from_mut
// ============================================================================

/// What the guard took is found while the guard holds it.
///
/// The one the thirty-two byte section cannot reach: at that size a `mem::swap`
/// is a few loads and stores, and at this one it is a call into the C library
/// with the secret as its argument.
#[test]
fn test_a_guarded_wide_value_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = Wide::default();

    giving(&mut source.0);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        capture!();

        core::mem::forget(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "four kilobytes guarded, and kept");

    core::hint::black_box(&source);

    Ok(())
}

/// Taking four kilobytes leaves nothing once the guard is let go.
#[test]
fn test_guarding_a_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        capture!();

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the swap left, and then the absence
        // below is about that call and not about the swap.
        drop(guard);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes guarded");

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Wide>: ownership
// ============================================================================

/// Four kilobytes guarded and given away leave nothing where they were.
#[test]
fn test_a_guarded_wide_value_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: before the capture, because this is the operation.
        let_go(guard);

        capture!();
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "four kilobytes given away",
    );

    Ok(())
}

// ============================================================================
// ZeroizingGuard<Wide>::drop
// ============================================================================

/// Dropping the guard leaves nothing.
#[test]
fn test_dropping_a_guarded_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    elenchos!({
        let guard = ZeroizingGuard::from_mut(&mut source);

        // CORRECTNESS: before the capture, because this is the operation.
        drop(guard);

        capture!();
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes dropped");

    Ok(())
}

// ============================================================================
// ZeroizingMutGuard<Vec<u8>>
// ============================================================================

/// What the guard borrowed is found while the guard holds it.
///
/// Where it is found is the caller's own variable, because that is the one
/// place a borrowing guard ever puts anything.
#[test]
fn test_a_borrowed_vec_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    elenchos!({
        let guard = ZeroizingMutGuard::from(&mut source);

        capture!();

        hold_on(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec borrowed, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// Borrowing a vec of one size, and letting the guard go.
macro_rules! a_borrowed_vec {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            elenchos!({
                let guard = ZeroizingMutGuard::from(&mut source);

                // CORRECTNESS: before the capture, because the drop is the
                // operation. A borrowing guard moves nothing on the way in —
                // what it does is wipe the caller's value on the way out.
                drop(guard);

                capture!();
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes borrowed", $of),
            );

            Ok(())
        }
    };
}

a_borrowed_vec!(test_borrowing_a_vec_of_32_leaves_nothing, 32);
a_borrowed_vec!(test_borrowing_a_vec_of_64_leaves_nothing, 64);
a_borrowed_vec!(test_borrowing_a_vec_of_128_leaves_nothing, 128);
a_borrowed_vec!(test_borrowing_a_vec_of_512_leaves_nothing, 512);
a_borrowed_vec!(test_borrowing_a_vec_of_1024_leaves_nothing, 1024);
a_borrowed_vec!(test_borrowing_a_vec_of_4096_leaves_nothing, 4096);
a_borrowed_vec!(test_borrowing_a_vec_of_16384_leaves_nothing, 16384);
a_borrowed_vec!(test_borrowing_a_vec_of_65536_leaves_nothing, 65536);

// ============================================================================
// ZeroizingMutGuard<Wide>
// ============================================================================

/// What the guard borrowed is found while the guard holds it.
#[test]
fn test_a_borrowed_wide_value_is_found_while_the_guard_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = Wide::default();

    giving(&mut source.0);

    elenchos!({
        let guard = ZeroizingMutGuard::from(&mut source);

        capture!();

        hold_on(guard);
    });

    let report = watch.snapshot()?;

    is_found(&report, "four kilobytes borrowed, and kept");

    core::hint::black_box(&source);

    Ok(())
}

/// Borrowing four kilobytes leaves nothing once the guard is let go.
///
/// The shape that caught the other guard: there, the swap moved the value and
/// left sixteen bytes of it in a vector register on `aarch64`. Here nothing is
/// moved, so there should be nothing to find.
#[test]
fn test_borrowing_a_wide_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    elenchos!({
        let guard = ZeroizingMutGuard::from(&mut source);

        // CORRECTNESS: before the capture, because the drop is the operation.
        drop(guard);

        capture!();
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "four kilobytes borrowed");

    Ok(())
}

// ============================================================================
// ZeroizingMutGuard: ownership
// ============================================================================

/// A borrowing guard given away leaves nothing where it was.
///
/// What travels is a `&mut`, so there is nothing for the move to copy. This is
/// the test that says so rather than the type signature.
#[test]
fn test_a_borrowing_guard_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = Wide::default();

    giving(&mut source.0);

    elenchos!({
        let guard = ZeroizingMutGuard::from(&mut source);

        // CORRECTNESS: before the capture, because this is the operation.
        let_go(guard);

        capture!();
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "a borrowing guard given away",
    );

    Ok(())
}
