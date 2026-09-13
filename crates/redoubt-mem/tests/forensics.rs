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

use redoubt_forensics::{Forensics, Reason, Report, forensics};

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
fn ours(into: &mut [u8]) {
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
fn theirs(into: &mut [u8]) {
    let of = core::hint::black_box(SECRET.len());

    // SAFETY: `into` is at least `of` long, `of` is the length of `SECRET`,
    // and a constant and a local are different allocations.
    unsafe { core::ptr::copy_nonoverlapping(SECRET.as_ptr(), into.as_mut_ptr(), of) };

    wipe(into);
}

fn line(what: &str, now: &Report, before: &Report) {
    println!("  {what:<24} {now}");
    println!("  {:<24} {}", "", now.against(before));
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
fn test_what_each_copy_leaves_behind() -> Result<(), Reason> {
    let needle = backwards();
    let mut watch = Forensics::watching(&needle)?;
    let mut scratch = vec![0_u8; SECRET.len()];

    let quiet = watch.snapshot()?;

    // Ours first. Anything the other one leaves in a register nothing writes
    // over would still be there afterwards, and would be counted against this
    // one.
    let after_ours = forensics!(watch, { ours(&mut scratch) })?;
    let after_theirs = forensics!(watch, { theirs(&mut scratch) })?;

    // Last, and only now: a copy in plain sight. Everything above is worth
    // what this line is worth.
    let planted = core::hint::black_box(SECRET.to_vec());
    let control = watch.snapshot()?;

    println!();
    println!("  {:<24} {quiet}", "nothing copied yet");
    line("redoubt_mem", &after_ours, &quiet);
    line("core::ptr", &after_theirs, &after_ours);
    println!();
    line("a copy in plain sight", &control, &after_theirs);
    println!();
    println!(
        "  the sweep {} the planted copy",
        if control.found {
            "FOUND"
        } else {
            "DID NOT FIND — nothing above is worth anything"
        },
    );
    println!();

    assert!(
        control.found,
        "the sweep reaches nowhere, so no zero here means anything"
    );

    assert!(
        !after_ours.found,
        "the whole secret survived this crate's copy:\nbefore {quiet}\nafter  {after_ours}",
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
fn test_two_hundred_copies_add_up_to_nothing() -> Result<(), Reason> {
    const ROUNDS: usize = 200;

    let needle = backwards();
    let mut watch = Forensics::watching(&needle)?;
    let mut scratch = vec![0_u8; SECRET.len()];

    let before = watch.snapshot()?;

    let after = forensics!(watch, {
        for _ in 0..ROUNDS {
            ours(&mut scratch);
        }
    })?;

    let planted = core::hint::black_box(SECRET.to_vec());
    let control = watch.snapshot()?;

    println!();
    println!("  {:<24} {before}", "nothing copied yet");
    line(&format!("{ROUNDS} copies"), &after, &before);
    line("a copy in plain sight", &control, &after);
    println!();

    assert!(
        control.found,
        "the sweep reaches nowhere, so no zero here means anything"
    );

    assert!(
        !after.found,
        "the whole secret surfaced after {ROUNDS} copies:\nbefore {before}\nafter  {after}",
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
fn ours_at(of: usize, into: &mut [u8]) {
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
fn test_no_size_of_copy_leaves_anything_behind() -> Result<(), Reason> {
    let needle = backwards();
    let mut watch = Forensics::watching(&needle)?;
    let mut scratch = vec![0_u8; BIG.len()];

    let before = watch.snapshot()?;

    println!();
    println!("  {:<24} {before}", "nothing copied yet");

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
        let after = forensics!(watch, { ours_at(of, &mut scratch[..of]) })?;

        line(&format!("{of} bytes"), &after, &before);

        assert!(
            !after.found,
            "the whole secret survived a copy of {of} bytes: {after}"
        );

        let moved = after.against(&before);

        assert!(
            moved.is_noise(),
            "a copy of {of} bytes moved the score: {moved}"
        );
    }

    println!();

    drop(core::hint::black_box(scratch));

    Ok(())
}
