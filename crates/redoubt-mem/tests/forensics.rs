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
//! # The destination is wiped
//!
//! A copy that worked leaves the secret in the destination, which would be
//! found and would say nothing. So each one is wiped, byte by byte and
//! volatile, before the photograph. Whatever is left after that was not in
//! memory when the copy ended.
//!
//! # And the control is last
//!
//! A sweep that reaches nowhere answers exactly like a clean process, so the
//! zeros above are worth what the last line is worth: a copy in plain sight,
//! planted only once everything else has been measured.

#![cfg(target_os = "linux")]

use redoubt_forensics::{AnyError, Forensics, forensics};

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives where nothing can write and the sweep never reads it
/// as a copy.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

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

/// The secret through this crate's copy, and the destination cleared behind
/// it.
#[inline(never)]
fn copy_ours(into: &mut [u8]) {
    // SAFETY: `into` is at least as long as `SECRET`, and a constant and a
    // local are different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), into.as_mut_ptr(), SECRET.len()) };

    wipe(into);
}

/// The same through the one the language gives you.
///
/// The length goes through `black_box` so the compiler cannot see it: a
/// length it can see is a copy it unrolls, and an unrolled copy is not the
/// thing this crate was written about. Hidden, it becomes a call to the C
/// library's `memcpy`, which is.
#[inline(never)]
fn copy_theirs(into: &mut [u8]) {
    let of = core::hint::black_box(SECRET.len());

    // SAFETY: `into` is at least `of` long, `of` is the length of `SECRET`,
    // and a constant and a local are different allocations.
    unsafe { core::ptr::copy_nonoverlapping(SECRET.as_ptr(), into.as_mut_ptr(), of) };

    wipe(into);
}

/// The secret exchanged into a second buffer through this crate's swap, and
/// both cleared behind it.
///
/// Both, because a swap leaves the value in the *other* place: wiping only one
/// would leave the secret in plain sight and measure nothing.
#[inline(never)]
fn swap_ours(secret: &mut [u8; 32], empty: &mut [u8; 32]) {
    redoubt_mem::swap(secret, empty);

    wipe(secret);
    wipe(empty);
}

/// The same through the one the language gives you.
///
/// `mem::swap` on a value this size is not a call into anything — the
/// compiler emits the loads and stores itself, through registers it picks.
/// Which is the point: what is being compared is not two libraries but a
/// routine that erases what it used against one that has no reason to.
#[inline(never)]
fn swap_theirs(secret: &mut [u8; 32], empty: &mut [u8; 32]) {
    core::mem::swap(secret, empty);

    wipe(secret);
    wipe(empty);
}

/// Neither copy is asserted against the other, and this one is asserted about
/// itself.
///
/// What the library's copy leaves is a property of the machine's libc, so a
/// test that demanded it leak would fail on musl and pass on glibc for
/// reasons that have nothing to do with this crate. It is printed.
///
/// What *this* crate's copy leaves is a promise it makes, so it is asserted.
#[test]
fn test_what_each_copy_leaves_behind() -> Result<(), AnyError> {
    let needle = backwards();
    let mut watch = Forensics::watching(&needle)?;
    let mut scratch = vec![0_u8; SECRET.len()];

    let report_before = watch.snapshot()?;

    // Ours first. Anything the other one leaves in a register nothing writes
    // over would still be there afterwards, and would be counted against this
    // one.
    let report_after_ours = forensics!(watch, { copy_ours(&mut scratch) });
    let report_after_theirs = forensics!(watch, { copy_theirs(&mut scratch) });

    // Last, and only now: a copy in plain sight. Everything above is worth
    // what this line is worth.
    let planted = core::hint::black_box(SECRET.to_vec());
    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_before.summary("nothing copied yet");
    report_after_ours.summary_against(&report_before, "redoubt_mem");
    report_after_theirs.summary_against(&report_after_ours, "core::ptr");
    println!();
    report_in_plain_sight.summary_against(&report_after_theirs, "a copy in plain sight");
    println!();
    println!(
        "  the sweep {} the planted copy",
        if report_in_plain_sight.found {
            "FOUND"
        } else {
            "DID NOT FIND — nothing above is worth anything"
        },
    );
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep reaches nowhere, so no zero here means anything"
    );

    assert!(
        !report_after_ours.found,
        "the whole secret survived this crate's copy:\n\
         before {report_before}\nafter  {report_after_ours}",
    );

    drop(core::hint::black_box((planted, scratch)));

    Ok(())
}

/// The same copy two hundred times, because one round leaving nothing is a
/// weaker claim than it looks.
///
/// A piece that survives one round in fifty would not show once and would show
/// plainly at two hundred. The destination is wiped every time, so what
/// accumulates is only what the copy itself left.
#[test]
fn test_two_hundred_copies_add_up_to_nothing() -> Result<(), AnyError> {
    const ROUNDS: usize = 200;

    let needle = backwards();
    let mut watch = Forensics::watching(&needle)?;
    let mut scratch = vec![0_u8; SECRET.len()];

    let report_before = watch.snapshot()?;

    let report_after = forensics!(watch, {
        for _ in 0..ROUNDS {
            copy_ours(&mut scratch);
        }
    });

    let planted = core::hint::black_box(SECRET.to_vec());
    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_before.summary("nothing copied yet");
    report_after.summary_against(&report_before, &format!("{ROUNDS} copies"));
    report_in_plain_sight.summary_against(&report_after, "a copy in plain sight");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep reaches nowhere, so no zero here means anything"
    );

    assert!(
        !report_after.found,
        "the whole secret surfaced after {ROUNDS} copies:\n\
         before {report_before}\nafter  {report_after}",
    );

    drop(core::hint::black_box((planted, scratch)));

    Ok(())
}

/// The secret over and over, in a constant, so that a copy of any size has
/// something to carry.
///
/// A `const`, so it lives where nothing can write and the sweep never reads
/// the source as a leak.
const TIMES: usize = 256;

const BIG: [u8; SECRET.len() * TIMES] = {
    let mut all = [0_u8; SECRET.len() * TIMES];
    let mut at = 0;

    while at < all.len() {
        all[at] = SECRET[at % SECRET.len()];
        at += 1;
    }

    all
};

/// A copy of that many bytes, and the destination cleared behind it.
#[inline(never)]
fn copy_ours_at(of: usize, into: &mut [u8]) {
    // SAFETY: `into` is `BIG.len()` long and `of` never passes that, and a
    // constant and a local are different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(BIG.as_ptr(), into.as_mut_ptr(), of) };

    wipe(into);
}

/// Nothing is left at any size, which is what tells a leak in the copy apart
/// from a leak in whatever called it.
///
/// The routine takes a different path by length — the general registers up to
/// thirty-two bytes, the vector loop up to five hundred and twelve, and the
/// string move past that — and a caller that leaks only when its buffers grow
/// looks exactly like a copy that leaks only on one of those paths. This is
/// the cheaper of the two to rule out.
#[test]
fn test_no_size_of_copy_leaves_anything_behind() -> Result<(), AnyError> {
    let needle = backwards();
    let mut watch = Forensics::watching(&needle)?;
    let mut scratch = vec![0_u8; BIG.len()];

    let report_before = watch.snapshot()?;

    println!();
    println!("  {:<24} {report_before}", "nothing copied yet");

    for of in [
        32_usize,
        33,
        63,
        64,
        65,
        127,
        128,
        129,
        511,
        512,
        513,
        1024,
        4096,
        BIG.len(),
    ] {
        let report_after = forensics!(watch, { copy_ours_at(of, &mut scratch[..of]) });

        report_after.summary_against(&report_before, &format!("{of} bytes"));

        assert!(
            !report_after.found,
            "the whole secret survived a copy of {of} bytes: {report_after}"
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "a copy of {of} bytes moved the score: {delta}"
        );
    }

    println!();

    drop(core::hint::black_box(scratch));

    Ok(())
}

// ============================================================================
// swap
// ============================================================================

/// What each exchange leaves behind, weighed the same way.
///
/// Neither is asserted against the other. What `mem::swap` leaves is a
/// property of what the compiler chose to move the bytes with, so a test that
/// demanded it leak would be a test of this month's LLVM. It is printed.
///
/// What *this* crate's swap leaves is a promise it makes, so it is asserted.
///
/// Thirty-two bytes inline on purpose: that is the shape where a swap moves
/// the value itself rather than a header, and where what it moved it through
/// is nobody's to choose.
#[test]
fn test_what_each_swap_leaves_behind() -> Result<(), AnyError> {
    let needle = backwards();
    let mut watch = Forensics::watching(&needle)?;

    let report_before = watch.snapshot()?;

    // Ours first, for the reason the copy's comparison gives.
    let report_after_ours = forensics!(watch, {
        let mut secret = [0_u8; 32];
        let mut empty = [0_u8; 32];

        // SAFETY: a constant and a local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), secret.as_mut_ptr(), 32) };

        swap_ours(&mut secret, &mut empty);

        core::hint::black_box((&secret, &empty));
    });

    let report_after_theirs = forensics!(watch, {
        let mut secret = [0_u8; 32];
        let mut empty = [0_u8; 32];

        // SAFETY: as above.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), secret.as_mut_ptr(), 32) };

        swap_theirs(&mut secret, &mut empty);

        core::hint::black_box((&secret, &empty));
    });

    // Last, and only now: a copy in plain sight. Everything above is worth
    // what this line is worth.
    let planted = core::hint::black_box(SECRET.to_vec());
    let report_in_plain_sight = watch.snapshot()?;

    println!();
    report_before.summary("nothing swapped yet");
    report_after_ours.summary_against(&report_before, "redoubt_mem");
    report_after_theirs.summary_against(&report_after_ours, "core::mem");
    println!();
    report_in_plain_sight.summary_against(&report_after_theirs, "a copy in plain sight");
    println!();

    assert!(
        report_in_plain_sight.found,
        "the sweep reaches nowhere, so no zero here means anything"
    );

    assert!(
        !report_after_ours.found,
        "the whole secret survived this crate's swap:\n\
         before {report_before}\nafter  {report_after_ours}",
    );

    let delta = report_after_ours.against(&report_before);

    assert!(
        delta.is_noise(),
        "this crate's swap moved the score: {delta}"
    );

    drop(core::hint::black_box(planted));

    Ok(())
}

/// Nothing is left at any size, which is what tells a leak in the swap apart
/// from a leak in whatever called it.
///
/// The routine takes a different path by length — the vector loop down to a
/// single byte, one bit of the length at a time — and a caller that leaks only
/// when its buffers grow looks exactly like a swap that leaks on one of those
/// paths. This is the cheaper of the two to rule out.
#[test]
fn test_no_size_of_swap_leaves_anything_behind() -> Result<(), AnyError> {
    let needle = backwards();
    let mut watch = Forensics::watching(&needle)?;

    let mut secret = vec![0_u8; BIG.len()];
    let mut empty = vec![0_u8; BIG.len()];

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing swapped yet");

    for of in [
        32_usize,
        33,
        63,
        64,
        65,
        127,
        128,
        129,
        511,
        512,
        513,
        1024,
        4096,
        BIG.len(),
    ] {
        let report_after = forensics!(watch, {
            // SAFETY: `secret` is `BIG.len()` long and `of` never passes that,
            // and a constant and a local are different allocations.
            unsafe { redoubt_mem::copy_nonoverlapping(BIG.as_ptr(), secret.as_mut_ptr(), of) };

            // SAFETY: two different allocations, both `BIG.len()` long.
            unsafe {
                redoubt_mem::swap_nonoverlapping(secret.as_mut_ptr(), empty.as_mut_ptr(), of);
            }

            wipe(&mut secret[..of]);
            wipe(&mut empty[..of]);
        });

        report_after.summary_against(&report_before, &format!("{of} bytes"));

        assert!(
            !report_after.found,
            "the whole secret survived a swap of {of} bytes: {report_after}"
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "a swap of {of} bytes moved the score: {delta}"
        );
    }

    println!();

    drop(core::hint::black_box((secret, empty)));

    Ok(())
}
