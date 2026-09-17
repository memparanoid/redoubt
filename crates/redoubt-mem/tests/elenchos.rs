// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each copy leaves behind, weighed rather than named.
//!
//! # Why this as well as `registers.rs`
//!
//! That file reads the registers the assembly *says* it uses: `rax`, `rcx`,
//! `xmm0`, `xmm1`, or `x3` and `v0-v3`. It is exact, and it is exactly as good
//! as that list. A byte left somewhere nobody wrote down reads as clean.
//!
//! The list was wrong once before, and not by a little. The residue this crate
//! exists for lived in `zmm16` and `zmm17`, which no instrument was looking at
//! because no instrument had been told to. A capture that reads the whole
//! register file cannot make that mistake, which is the one thing it is better
//! at.
//!
//! So: the registers become memory, the sweep finds them like anything else,
//! and the score says how much of the secret is in the process. No list.
//!
//! # Where the wipe goes
//!
//! A copy that worked leaves the secret in its destination, which would be
//! found and would say nothing. So the destination is wiped — but **after** the
//! capture, never before. Wiped first, the wipe's own frames and registers land
//! on what the copy left, and the absence would be the wipe's doing.
//!
//! The wipe is volatile and one byte at a time. A `fill` is a call to `memset`,
//! which is the other half of the library this is measuring.
//!
//! # Two tests for every claim
//!
//! Each section opens with the same call and nothing wiped after it, and that
//! one has to be **found** — in the destination, which is where a copy puts
//! things. An absence is worth exactly as much as that presence.
//!
//! # One size per test
//!
//! The routine takes a different path by length — the general registers up to
//! thirty-two bytes, the vector loop up to five hundred and twelve, the string
//! move past that — and each is its own test, because the sweep reads the whole
//! process and a size that leaks would be found by every size measured after it
//! in the same one.

#![cfg(target_os = "linux")]

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, elenchos};

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// How many times the secret goes into the constant a sized copy reads from.
const TIMES: usize = 256;

/// The secret over and over, in a constant, so that a copy of any size has
/// something to carry.
///
/// A `const`, for the reason [`SECRET`] is one: the source of a copy must not
/// be somewhere the sweep reads, or every measurement would find it.
const BIG: [u8; SECRET.len() * TIMES] = {
    let mut all = [0_u8; SECRET.len() * TIMES];
    let mut at = 0;

    while at < all.len() {
        all[at] = SECRET[at % SECRET.len()];
        at += 1;
    }

    all
};

/// One round leaving nothing is a weaker claim than it looks.
///
/// A piece surviving one round in fifty would not show once and would show
/// plainly at two hundred.
const ROUNDS: usize = 200;

/// The needle, built from its last byte to its first.
///
/// Backwards from the start and never turned around: a `to_vec` followed by a
/// `reverse` would put the secret forwards on the heap for as long as it takes
/// to turn it over, and a vectorised reverse can spill half of it on the way.
/// That is the very thing being measured, and the test does not get to cause
/// it.
fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// Every byte of it back to zero, so that what survives is not memory.
///
/// Volatile and one at a time: a `fill` is a call to `memset`, which is the
/// other half of the library this is measuring.
fn wipe(into: &mut [u8]) {
    for at in 0..into.len() {
        // SAFETY: in bounds of a live slice.
        unsafe { into.as_mut_ptr().add(at).write_volatile(0) };
    }
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

// ============================================================================
// copy_nonoverlapping
// ============================================================================

/// A copy is found in its destination.
///
/// The same call as every test below with the wipe left out, so what it finds
/// is the copy's own result in the buffer the copy was given. Nothing is
/// planted: a copy the test put somewhere of its own choosing would vouch for
/// that place and not for this one.
#[test]
fn test_a_copy_is_found_in_its_destination() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut scratch = vec![0_u8; SECRET.len()];

    elenchos!({
        // SAFETY: `scratch` is exactly the secret's length, and a constant and
        // a heap block are different allocations.
        unsafe {
            redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), scratch.as_mut_ptr(), SECRET.len());
        }

        capture!();
    });

    let report = watch.snapshot()?;

    is_found(&report, "a copy, left in its destination");

    wipe(&mut scratch);

    drop(core::hint::black_box(scratch));

    Ok(())
}

/// Copying leaves nothing once the destination is emptied.
#[test]
fn test_copying_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut scratch = vec![0_u8; SECRET.len()];

    elenchos!({
        // SAFETY: as above.
        unsafe {
            redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), scratch.as_mut_ptr(), SECRET.len());
        }

        capture!();

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the copy left, and then the absence
        // below is about that call and not about the copy.
        wipe(&mut scratch);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing copied yet",
        &report_after,
        "a copy",
    );

    drop(core::hint::black_box(scratch));

    Ok(())
}

/// The same copy two hundred times.
///
/// Its own test rather than one more round in the one above, because the two
/// fail for different reasons. One round failing is a leak in a single copy.
/// Only this one failing is something that accumulates — a residue that
/// survives one round in fifty.
#[test]
fn test_two_hundred_copies_leave_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut scratch = vec![0_u8; SECRET.len()];

    elenchos!({
        for _ in 0..ROUNDS {
            // SAFETY: as above.
            unsafe {
                redoubt_mem::copy_nonoverlapping(
                    SECRET.as_ptr(),
                    scratch.as_mut_ptr(),
                    SECRET.len(),
                );
            }
        }

        capture!();

        // CORRECTNESS: after the capture, for the reason the test above gives.
        wipe(&mut scratch);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing copied yet",
        &report_after,
        &format!("{ROUNDS} copies"),
    );

    drop(core::hint::black_box(scratch));

    Ok(())
}

/// A copy of one size, and the destination emptied behind it.
macro_rules! copied {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut scratch = vec![0_u8; $of];

            elenchos!({
                // SAFETY: `scratch` is `$of` long, `$of` never passes `BIG`'s
                // length, and a constant and a heap block are different
                // allocations.
                unsafe {
                    redoubt_mem::copy_nonoverlapping(BIG.as_ptr(), scratch.as_mut_ptr(), $of);
                }

                capture!();

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the copy left, and then the
                // absence below is about that call and not about the copy.
                wipe(&mut scratch);
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                "nothing copied yet",
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

/// A swap is found in the buffer it moved the secret into.
///
/// Thirty-two bytes inline on purpose: that is the shape where a swap moves
/// the value itself rather than a header, and where what it moved it through is
/// nobody's to choose.
#[test]
fn test_a_swap_is_found_where_it_moved_the_secret() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut secret = [0_u8; 32];
    let mut empty = [0_u8; 32];

    // SAFETY: a constant and a local are different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), secret.as_mut_ptr(), 32) };

    elenchos!({
        redoubt_mem::swap(&mut secret, &mut empty);

        capture!();
    });

    let report = watch.snapshot()?;

    is_found(&report, "a swap, left where it moved it");

    wipe(&mut secret);
    wipe(&mut empty);

    core::hint::black_box((&secret, &empty));

    Ok(())
}

/// Swapping leaves nothing once both buffers are emptied.
///
/// Both, because a swap leaves the value in the *other* place: emptying only
/// one would leave the secret in plain sight and measure nothing.
#[test]
fn test_swapping_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut secret = [0_u8; 32];
    let mut empty = [0_u8; 32];

    // SAFETY: a constant and a local are different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), secret.as_mut_ptr(), 32) };

    elenchos!({
        redoubt_mem::swap(&mut secret, &mut empty);

        capture!();

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the swap left, and then the absence
        // below is about that call and not about the swap.
        wipe(&mut secret);
        wipe(&mut empty);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing swapped yet",
        &report_after,
        "a swap",
    );

    core::hint::black_box((&secret, &empty));

    Ok(())
}

// ============================================================================
// swap_nonoverlapping
// ============================================================================

/// A sized swap is found in the buffer it moved the secret into.
#[test]
fn test_a_sized_swap_is_found_where_it_moved_the_secret() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut secret = vec![0_u8; SECRET.len()];
    let mut empty = vec![0_u8; SECRET.len()];

    // SAFETY: a constant and a heap block are different allocations.
    unsafe {
        redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), secret.as_mut_ptr(), SECRET.len());
    }

    elenchos!({
        // SAFETY: two different allocations, both the secret's length.
        unsafe {
            redoubt_mem::swap_nonoverlapping(
                secret.as_mut_ptr(),
                empty.as_mut_ptr(),
                SECRET.len(),
            );
        }

        capture!();
    });

    let report = watch.snapshot()?;

    is_found(&report, "a sized swap, left where it moved it");

    wipe(&mut secret);
    wipe(&mut empty);

    drop(core::hint::black_box((secret, empty)));

    Ok(())
}

/// A swap of one size, and both buffers emptied behind it.
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

            elenchos!({
                // SAFETY: two different allocations, both `$of` long.
                unsafe {
                    redoubt_mem::swap_nonoverlapping(
                        secret.as_mut_ptr(),
                        empty.as_mut_ptr(),
                        $of,
                    );
                }

                capture!();

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the swap left, and then the
                // absence below is about that call and not about the swap.
                wipe(&mut secret);
                wipe(&mut empty);
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                "nothing swapped yet",
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
