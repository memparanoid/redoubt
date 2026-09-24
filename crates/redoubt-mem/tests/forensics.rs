// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each copy and swap leaves behind, weighed over the whole register file
//! rather than over the registers the assembly names.
//!
//! Run under `nextest`: the sweep reads the whole process, and `cargo test`
//! shares one between tests.

#![cfg(target_os = "linux")]

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, forensics};

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// How many times the secret goes into [`BIG`].
const TIMES: usize = 256;

/// The secret over and over, in a constant the sweep does not read, so that a
/// copy of any size has something to carry.
const BIG: [u8; SECRET.len() * TIMES] = {
    let mut all = [0_u8; SECRET.len() * TIMES];
    let mut at = 0;

    while at < all.len() {
        all[at] = SECRET[at % SECRET.len()];
        at += 1;
    }

    all
};

/// Copies in a row: a residue that survives one copy in fifty shows here and
/// not in a single one.
const ROUNDS: usize = 200;

/// The needle, built from its last byte to its first and never turned around:
/// the forward bytes must not exist in this process.
fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// Every byte back to zero, volatile and one at a time: a `fill` is a call to
/// `memset`, which is the other half of the library this is measuring.
fn wipe(into: &mut [u8]) {
    for at in 0..into.len() {
        // SAFETY: in bounds of a live slice.
        unsafe { into.as_mut_ptr().add(at).write_volatile(0) };
    }
}

/// Asserts the secret was found. Without a presence, an absence cannot be told
/// apart from a sweep that reaches nowhere.
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

/// Asserts the secret is gone: not whole, no run past `QUIET`, and a score that
/// did not move. Each alone passes a process that kept part of it.
fn leaves_nothing(report_before: &Report, before: &str, report_after: &Report, what: &str) {
    println!();
    report_before.summary(before);
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

/// Thirty-two bytes of the secret in a box, through the copy being measured
/// elsewhere in this file.
fn hold() -> Box<[u8; 32]> {
    let mut held = Box::new([0_u8; 32]);

    // SAFETY: a constant and a heap block are different allocations, and both
    // are thirty-two bytes.
    unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), held.as_mut_ptr(), 32) };

    held
}

// ============================================================================
// copy_nonoverlapping
// ============================================================================

#[test]
fn test_a_copy_is_found_in_its_destination() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut scratch = vec![0_u8; SECRET.len()];

    forensics!({
        capture(|| {
            // SAFETY: `scratch` is exactly the secret's length, and a constant
            // and a heap block are different allocations.
            unsafe {
                redoubt_mem::copy_nonoverlapping(
                    SECRET.as_ptr(),
                    scratch.as_mut_ptr(),
                    SECRET.len(),
                );
            }
        });
    });

    let report = watch.snapshot()?;

    is_found(&report, "a copy, left in its destination");

    wipe(&mut scratch);

    drop(core::hint::black_box(scratch));

    Ok(())
}

#[test]
fn test_copying_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut scratch = vec![0_u8; SECRET.len()];

    forensics!({
        capture(|| {
            // SAFETY: `scratch` is exactly the secret's length, and a constant
            // and a heap block are different allocations.
            unsafe {
                redoubt_mem::copy_nonoverlapping(
                    SECRET.as_ptr(),
                    scratch.as_mut_ptr(),
                    SECRET.len(),
                );
            }
        });

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut scratch);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, "nothing held yet", &report_after, "a copy");

    drop(core::hint::black_box(scratch));

    Ok(())
}

#[test]
fn test_two_hundred_copies_leave_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut scratch = vec![0_u8; SECRET.len()];

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                // SAFETY: `scratch` is exactly the secret's length, and a
                // constant and a heap block are different allocations.
                unsafe {
                    redoubt_mem::copy_nonoverlapping(
                        SECRET.as_ptr(),
                        scratch.as_mut_ptr(),
                        SECRET.len(),
                    );
                }
            }
        });

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut scratch);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &report_after,
        &format!("{ROUNDS} copies"),
    );

    drop(core::hint::black_box(scratch));

    Ok(())
}

macro_rules! copied {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut scratch = vec![0_u8; $of];

            forensics!({
                capture(|| {
                    // SAFETY: `scratch` is `$of` long, `$of` never passes
                    // `BIG`'s length, and a constant and a heap block are
                    // different allocations.
                    unsafe {
                        redoubt_mem::copy_nonoverlapping(BIG.as_ptr(), scratch.as_mut_ptr(), $of);
                    }
                });

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                wipe(&mut scratch);
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                "nothing held yet",
                &report_after,
                &format!("a copy of {} bytes", $of),
            );

            drop(core::hint::black_box(scratch));

            Ok(())
        }
    };
}

copied!(test_copying_32_bytes_leaves_nothing, 32);
copied!(test_copying_33_bytes_leaves_nothing, 33);
copied!(test_copying_63_bytes_leaves_nothing, 63);
copied!(test_copying_64_bytes_leaves_nothing, 64);
copied!(test_copying_65_bytes_leaves_nothing, 65);
copied!(test_copying_127_bytes_leaves_nothing, 127);
copied!(test_copying_128_bytes_leaves_nothing, 128);
copied!(test_copying_129_bytes_leaves_nothing, 129);
copied!(test_copying_511_bytes_leaves_nothing, 511);
copied!(test_copying_512_bytes_leaves_nothing, 512);
copied!(test_copying_513_bytes_leaves_nothing, 513);
copied!(test_copying_1024_bytes_leaves_nothing, 1024);
copied!(test_copying_4096_bytes_leaves_nothing, 4096);
copied!(test_copying_8192_bytes_leaves_nothing, 8192);

// ============================================================================
// swap
// ============================================================================

#[test]
fn test_a_swap_is_found_where_it_moved_the_secret() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut secret = hold();
    let mut empty = Box::new([0_u8; 32]);

    forensics!({
        capture(|| redoubt_mem::swap(&mut *secret, &mut *empty));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a swap, left where it moved it");

    wipe(&mut *empty);

    drop(core::hint::black_box((secret, empty)));

    Ok(())
}

#[test]
fn test_swapping_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut secret = hold();
    let mut empty = Box::new([0_u8; 32]);

    forensics!({
        capture(|| redoubt_mem::swap(&mut *secret, &mut *empty));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Only the side the secret was swapped into is emptied: the side it
        // left is the swap's to leave empty, and emptying it here would keep
        // this green for a swap that only copied.
        wipe(&mut *empty);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, "nothing held yet", &report_after, "a swap");

    drop(core::hint::black_box((secret, empty)));

    Ok(())
}

// ============================================================================
// swap_nonoverlapping
// ============================================================================

#[test]
fn test_a_sized_swap_is_found_where_it_moved_the_secret() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut secret = vec![0_u8; SECRET.len()];
    let mut empty = vec![0_u8; SECRET.len()];

    // SAFETY: a constant and a heap block are different allocations.
    unsafe {
        redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), secret.as_mut_ptr(), SECRET.len());
    }

    forensics!({
        capture(|| {
            // SAFETY: two different allocations, both the secret's length.
            unsafe {
                redoubt_mem::swap_nonoverlapping(
                    secret.as_mut_ptr(),
                    empty.as_mut_ptr(),
                    SECRET.len(),
                );
            }
        });
    });

    let report = watch.snapshot()?;

    is_found(&report, "a sized swap, left where it moved it");

    wipe(&mut empty);

    drop(core::hint::black_box((secret, empty)));

    Ok(())
}

macro_rules! swapped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut secret = vec![0_u8; $of];
            let mut empty = vec![0_u8; $of];

            // SAFETY: `secret` is `$of` long, `$of` never passes `BIG`'s
            // length, and a constant and a heap block are different
            // allocations.
            unsafe { redoubt_mem::copy_nonoverlapping(BIG.as_ptr(), secret.as_mut_ptr(), $of) };

            forensics!({
                capture(|| {
                    // SAFETY: two different allocations, both `$of` long.
                    unsafe {
                        redoubt_mem::swap_nonoverlapping(
                            secret.as_mut_ptr(),
                            empty.as_mut_ptr(),
                            $of,
                        );
                    }
                });

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                //
                // Only the side the secret was swapped into is emptied: the
                // side it left is the swap's to leave empty, and emptying it
                // here would keep this green for a swap that only copied.
                wipe(&mut empty);
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                "nothing held yet",
                &report_after,
                &format!("a swap of {} bytes", $of),
            );

            drop(core::hint::black_box((secret, empty)));

            Ok(())
        }
    };
}

swapped!(test_swapping_32_bytes_leaves_nothing, 32);
swapped!(test_swapping_33_bytes_leaves_nothing, 33);
swapped!(test_swapping_63_bytes_leaves_nothing, 63);
swapped!(test_swapping_64_bytes_leaves_nothing, 64);
swapped!(test_swapping_65_bytes_leaves_nothing, 65);
swapped!(test_swapping_127_bytes_leaves_nothing, 127);
swapped!(test_swapping_128_bytes_leaves_nothing, 128);
swapped!(test_swapping_129_bytes_leaves_nothing, 129);
swapped!(test_swapping_511_bytes_leaves_nothing, 511);
swapped!(test_swapping_512_bytes_leaves_nothing, 512);
swapped!(test_swapping_513_bytes_leaves_nothing, 513);
swapped!(test_swapping_1024_bytes_leaves_nothing, 1024);
swapped!(test_swapping_4096_bytes_leaves_nothing, 4096);
swapped!(test_swapping_8192_bytes_leaves_nothing, 8192);
