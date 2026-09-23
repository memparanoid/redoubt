// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a container leaves behind once it has been filled and let go.
//!
//! # Two tests for every claim
//!
//! An absence on its own says nothing: a sweep that reaches nowhere reports a
//! clean process, and so does a container that wiped everything. So each
//! section here opens with the same operation run against a container that is
//! never let go, and that one has to be **found**. Whatever the rest of the
//! section reports is worth exactly as much as that.
//!
//! Each pair stands on its own. A control somewhere else in the file would say
//! that the sweep reaches *something*, which is not the question: what has to
//! be reachable is where **this** container puts its bytes.
//!
//! # Why size is an axis, and why each size is its own test
//!
//! A container that leaks a secret of thirty-two bytes and not one of thirty
//! kilobytes would be a strange thing. The other way round is not strange at
//! all: a large buffer is reallocated on the way up, is copied through a
//! routine that takes a different path by length, and puts enough pressure on
//! the register allocator that the compiler starts spilling to stack slots
//! nobody clears.
//!
//! One test per size rather than a loop inside one, because the sweep reads
//! the whole process: a size that leaks leaves the secret in memory, and every
//! size measured after it in the same process finds that copy and is blamed
//! for it. Under `nextest` each test is a process of its own, so the size that
//! failed is the name of the test that failed.
//!
//! # What goes inside the block
//!
//! ```text
//! let mut source = vec![0_u8; 32];
//! giving(&mut source);                    // the test's own doing, outside
//!
//! forensics!({
//!     let mut held = RedoubtVec::new();   // everything the crate does,
//!     capture(|| held.replace_from_mut_slice(&mut source));
//!     drop(held);                         // and the drop once it is frozen
//! });
//!
//! let report_after = watch.snapshot()?;
//! ```
//!
//! Everything this crate does is inside, from the container being made to it
//! being let go. What stays outside is the fixture: the bytes the test itself
//! put somewhere, which the test answers for and the crate does not.
//!
//! # Why the drop comes after the capture
//!
//! `capture` freezes the registers and the stack — everything the operation
//! left, copied out before anything can write over it.
//! It does not read the heap, and does not have to: the photograph reads that
//! live, later.
//!
//! Every container here keeps its bytes on the heap, behind a `Box` or a
//! `Vec`. So the copy a container is legitimately holding is not in what the
//! capture froze, and that is what lets the drop come afterwards: it empties
//! the allocation before the photograph and touches nothing the capture
//! already took. An absence can then only be residue the operation left.
//!
//! # What an absence here is contingent on
//!
//! The indirection, and not the instrument. Take the `Box` out of
//! `RedoubtArray` so the bytes live in the struct — a stack local, copied into
//! every slot it is moved out of, with nothing left to empty them — and every
//! absence in its sections turns red with the whole secret surfacing, while
//! every presence stays green.
//!
//! That is what these tests are reading. A container that stops holding its
//! bytes behind a pointer stops passing, which is the whole point of measuring
//! rather than arguing.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place the secret could be. `nextest`, not `cargo test`.

#![cfg(target_os = "linux")]

use redoubt_alloc::{AllockedVec, RedoubtArray, RedoubtOption, RedoubtString, RedoubtVec};
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

/// The digits a byte is spelled with.
const HEX: [u8; 16] = *b"0123456789abcdef";

/// The needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

/// The secret over and over, into somewhere the caller already owns, by the
/// copy that erases what it used.
///
/// Not `to_vec` and not a plain assignment: both are whatever move the
/// compiler emits, and the test does not get to cause the thing it is
/// measuring.
fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// What every `AllockedVec` in this file holds.
///
/// As wide as the secret, and never `u8`. A vec of bytes moves its elements one
/// at a time, so a residue it leaves is single bytes scattered over registers
/// that go on overwriting each other — a run of one, which is what memory has
/// by accident and what no sweep can tell from noise. The residue is real and
/// the measurement of it is not: an absence over `u8` elements is not a weak
/// answer, it is no answer.
///
/// Measured. `drain_from` moved its values with a compiler move, which leaves a
/// copy wherever it likes and empties none of them. Over `u8` elements this
/// file read a clean process; over this one it read the whole secret, thirty-two
/// bytes wide.
type Block = [u8; SECRET.len()];

/// How many of those make up a size in bytes.
const fn blocks(of: usize) -> usize {
    of / SECRET.len()
}

/// The secret written out as hex, over and over, as a `String`.
///
/// A string holds text, so the secret has to be spelled to go into one, and
/// what the sweep looks for there is the spelling rather than the bytes.
///
/// Written one character at a time into room reserved up front. Neither
/// `push_str` nor `write!` would do: both are `memcpy`, and the string would
/// grow under them and leave the spelling in every block it outgrew — which is
/// the very thing being measured, caused by the measuring.
fn spelled(of: usize) -> String {
    let mut all = String::with_capacity(of);

    // SAFETY: every byte pushed is an ASCII hex digit, so what is built stays
    // valid UTF-8.
    let bytes = unsafe { all.as_mut_vec() };

    for at in 0..of {
        let byte = SECRET[(at / 2) % SECRET.len()];

        bytes.push(if at % 2 == 0 {
            HEX[(byte >> 4) as usize]
        } else {
            HEX[(byte & 0xF) as usize]
        });
    }

    all
}

/// One copy of that spelling, read from its last character to its first.
///
/// Built backwards from the start and never turned around, for the reason
/// every needle here is: the forward spelling must not exist in this process
/// even for as long as it takes to reverse it.
fn spelled_backwards() -> Vec<u8> {
    let mut backwards = Vec::with_capacity(SECRET.len() * 2);

    for byte in SECRET.iter().rev() {
        backwards.push(HEX[(byte & 0xF) as usize]);
        backwards.push(HEX[(byte >> 4) as usize]);
    }

    backwards
}

/// A string emptied by hand, a byte at a time and volatile.
///
/// For the one method that is handed text it does not own and never promised
/// to empty. A `String` does not clear itself when it is dropped, so leaving
/// that to the drop would find the spelling in the block the allocator just
/// took back and read it as the method's.
fn emptying(text: &mut str) {
    // SAFETY: every byte written is zero, which is valid UTF-8, and the length
    // is the string's own.
    let bytes = unsafe { text.as_bytes_mut() };

    for at in 0..bytes.len() {
        // SAFETY: in bounds of a live string.
        unsafe { bytes.as_mut_ptr().add(at).write_volatile(0) };
    }
}

/// Takes the value and lets it go, which runs its drop somewhere the caller
/// cannot see.
///
/// What handing one of these to somebody else is. Not inlined: a move within
/// one function is one the optimiser may fold away, and a measurement of what
/// a move leaves has to be sure a move happened.
#[inline(never)]
fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the value the same way and never lets it go.
///
/// The other half of each pair. The move is the same move, so whatever it
/// leaves behind is the same; what changes is that whoever took it is still
/// holding the secret when the photograph is taken.
#[inline(never)]
fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}

/// The photograph says the secret is there, which is what makes the rest of
/// the section mean anything.
///
/// Every absence below it is an absence in the same place, reached the same
/// way. If this one is quiet, the instrument is standing somewhere else and
/// nothing in the section is a measurement.
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
    report_before.summary("nothing filled yet");
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
// AllockedVec::push
// ============================================================================

/// What is pushed is found while the vec holds it.
///
/// The value comes out of the constant, which lives where nothing may write,
/// so the only writable copy in the process is the one `push` made.
#[test]
fn test_what_was_pushed_is_found_while_the_allocked_vec_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        capture(|| held.push(&mut { SECRET }))?;

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec pushed into, and kept");

    Ok(())
}

/// One size pushed in a block at a time, and let go.
///
/// A value taken by `push` is a value copied out of the caller's slot, and the
/// vec never reallocates here, so what is left is whatever those copies left.
macro_rules! an_allocked_vec_pushed_into {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                capture(|| -> Result<(), AnyError> {
                    for one in &mut source {
                        held.push(one)?;
                    }

                    Ok(())
                })?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes pushed into", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_pushed_into!(test_an_allocked_vec_of_32_pushed_into_leaves_nothing, 32);
an_allocked_vec_pushed_into!(test_an_allocked_vec_of_64_pushed_into_leaves_nothing, 64);
an_allocked_vec_pushed_into!(test_an_allocked_vec_of_128_pushed_into_leaves_nothing, 128);
an_allocked_vec_pushed_into!(test_an_allocked_vec_of_512_pushed_into_leaves_nothing, 512);
an_allocked_vec_pushed_into!(
    test_an_allocked_vec_of_1024_pushed_into_leaves_nothing,
    1024
);
an_allocked_vec_pushed_into!(
    test_an_allocked_vec_of_4096_pushed_into_leaves_nothing,
    4096
);
an_allocked_vec_pushed_into!(
    test_an_allocked_vec_of_16384_pushed_into_leaves_nothing,
    16384
);
an_allocked_vec_pushed_into!(
    test_an_allocked_vec_of_65536_pushed_into_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec::truncate
// ============================================================================

/// The tail is found while it is still the vec's.
///
/// What the absence below is measured against: the sweep reaches the storage a
/// truncation is about to cut, so a clean answer afterwards is the cut and not
/// the instrument. Before and not after, because the type hands back nothing it
/// removed — there is no `pop` — so a cut tail exists nowhere to be found.
#[test]
fn test_what_a_truncation_will_cut_is_found_before_it_is_cut() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        capture(|| held.push(&mut { SECRET }))?;

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec filled, before anything was cut");

    Ok(())
}

/// One size filled and cut back to nothing.
macro_rules! an_allocked_vec_truncated {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                for one in &mut source {
                    held.push(one)?;
                }

                capture(|| held.truncate(0));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes truncated", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_truncated!(test_an_allocked_vec_of_32_truncated_leaves_nothing, 32);
an_allocked_vec_truncated!(test_an_allocked_vec_of_64_truncated_leaves_nothing, 64);
an_allocked_vec_truncated!(test_an_allocked_vec_of_128_truncated_leaves_nothing, 128);
an_allocked_vec_truncated!(test_an_allocked_vec_of_512_truncated_leaves_nothing, 512);
an_allocked_vec_truncated!(test_an_allocked_vec_of_1024_truncated_leaves_nothing, 1024);
an_allocked_vec_truncated!(test_an_allocked_vec_of_4096_truncated_leaves_nothing, 4096);
an_allocked_vec_truncated!(
    test_an_allocked_vec_of_16384_truncated_leaves_nothing,
    16384
);
an_allocked_vec_truncated!(
    test_an_allocked_vec_of_65536_truncated_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec::drain_from
// ============================================================================

/// What was drained is found while the vec holds it.
#[test]
fn test_what_was_drained_is_found_while_the_allocked_vec_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![[0_u8; SECRET.len()]];

    giving(&mut source[0]);

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        capture(|| held.drain_from(&mut source))?;

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec drained into, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// One size drained out of a slice the caller owns.
///
/// The source is the caller's and the operation is what empties it, so this
/// section asks about two places at once: what the call left of its own, and
/// what it left in the slice it was handed.
macro_rules! an_allocked_vec_drained_into {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));
                capture(|| held.drain_from(&mut source))?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes drained into", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_drained_into!(test_an_allocked_vec_of_32_drained_into_leaves_nothing, 32);
an_allocked_vec_drained_into!(test_an_allocked_vec_of_64_drained_into_leaves_nothing, 64);
an_allocked_vec_drained_into!(test_an_allocked_vec_of_128_drained_into_leaves_nothing, 128);
an_allocked_vec_drained_into!(test_an_allocked_vec_of_512_drained_into_leaves_nothing, 512);
an_allocked_vec_drained_into!(
    test_an_allocked_vec_of_1024_drained_into_leaves_nothing,
    1024
);
an_allocked_vec_drained_into!(
    test_an_allocked_vec_of_4096_drained_into_leaves_nothing,
    4096
);
an_allocked_vec_drained_into!(
    test_an_allocked_vec_of_16384_drained_into_leaves_nothing,
    16384
);
an_allocked_vec_drained_into!(
    test_an_allocked_vec_of_65536_drained_into_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec::realloc_with_capacity
// ============================================================================

/// What was carried over is found while the vec holds it.
///
/// The photograph is taken with the new allocation still held, which is where
/// the reallocation put the bytes it copied.
#[test]
fn test_what_was_carried_over_is_found_while_the_allocked_vec_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        held.push(&mut { SECRET })?;

        capture(|| held.realloc_with_capacity(2));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec reallocated, and kept");

    Ok(())
}

/// One size carried into a wider allocation, and let go.
///
/// The only operation here that moves a secret from one allocation to another.
/// What the absence asks about is the block it outgrew, which the call empties
/// after it has copied out of it.
macro_rules! an_allocked_vec_reallocated {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                for one in &mut source {
                    held.push(one)?;
                }

                capture(|| held.realloc_with_capacity(blocks($of) * 2));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes reallocated", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_reallocated!(test_an_allocked_vec_of_32_reallocated_leaves_nothing, 32);
an_allocked_vec_reallocated!(test_an_allocked_vec_of_64_reallocated_leaves_nothing, 64);
an_allocked_vec_reallocated!(test_an_allocked_vec_of_128_reallocated_leaves_nothing, 128);
an_allocked_vec_reallocated!(test_an_allocked_vec_of_512_reallocated_leaves_nothing, 512);
an_allocked_vec_reallocated!(
    test_an_allocked_vec_of_1024_reallocated_leaves_nothing,
    1024
);
an_allocked_vec_reallocated!(
    test_an_allocked_vec_of_4096_reallocated_leaves_nothing,
    4096
);
an_allocked_vec_reallocated!(
    test_an_allocked_vec_of_16384_reallocated_leaves_nothing,
    16384
);
an_allocked_vec_reallocated!(
    test_an_allocked_vec_of_65536_reallocated_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec: ownership
// ============================================================================

/// A vec given away is found while whoever took it is holding it.
#[test]
fn test_an_allocked_vec_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        held.push(&mut { SECRET })?;

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "an allocked vec given away, and kept");

    Ok(())
}

/// One size given away.
macro_rules! an_allocked_vec_given_away {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                for one in &mut source {
                    held.push(one)?;
                }

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| let_go(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an allocked vec of {} bytes given away", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_given_away!(test_an_allocked_vec_of_32_given_away_leaves_nothing, 32);
an_allocked_vec_given_away!(test_an_allocked_vec_of_64_given_away_leaves_nothing, 64);
an_allocked_vec_given_away!(test_an_allocked_vec_of_128_given_away_leaves_nothing, 128);
an_allocked_vec_given_away!(test_an_allocked_vec_of_512_given_away_leaves_nothing, 512);
an_allocked_vec_given_away!(test_an_allocked_vec_of_1024_given_away_leaves_nothing, 1024);
an_allocked_vec_given_away!(test_an_allocked_vec_of_4096_given_away_leaves_nothing, 4096);
an_allocked_vec_given_away!(
    test_an_allocked_vec_of_16384_given_away_leaves_nothing,
    16384
);
an_allocked_vec_given_away!(
    test_an_allocked_vec_of_65536_given_away_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec::drop
// ============================================================================

/// One size dropped.
macro_rules! an_allocked_vec_dropped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                for one in &mut source {
                    held.push(one)?;
                }

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| drop(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an allocked vec of {} bytes dropped", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_dropped!(test_an_allocked_vec_of_32_dropped_leaves_nothing, 32);
an_allocked_vec_dropped!(test_an_allocked_vec_of_64_dropped_leaves_nothing, 64);
an_allocked_vec_dropped!(test_an_allocked_vec_of_128_dropped_leaves_nothing, 128);
an_allocked_vec_dropped!(test_an_allocked_vec_of_512_dropped_leaves_nothing, 512);
an_allocked_vec_dropped!(test_an_allocked_vec_of_1024_dropped_leaves_nothing, 1024);
an_allocked_vec_dropped!(test_an_allocked_vec_of_4096_dropped_leaves_nothing, 4096);
an_allocked_vec_dropped!(test_an_allocked_vec_of_16384_dropped_leaves_nothing, 16384);
an_allocked_vec_dropped!(test_an_allocked_vec_of_65536_dropped_leaves_nothing, 65536);

// ============================================================================
// RedoubtArray::replace_from_mut_array
// ============================================================================

/// What the array was filled from is found while the array holds it.
///
/// An array's size is in its type, so there is no sweep over sizes to make
/// here and one is the whole of it.
#[test]
fn test_a_redoubt_array_replaced_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        capture(|| held.replace_from_mut_array(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an array replaced, and kept");

    // By reference on purpose: `[u8; 32]` is `Copy`, so a `black_box` of it by
    // value makes one more copy on the stack, and the test would be measuring
    // itself.
    core::hint::black_box(&source);

    Ok(())
}

/// Once the array is let go, nothing of it is anywhere.
#[test]
fn test_a_redoubt_array_replaced_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        capture(|| held.replace_from_mut_array(&mut source));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation. See the header.
        drop(held);
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array replaced");

    Ok(())
}

// ============================================================================
// RedoubtArray: ownership
// ============================================================================

/// An array given away is found while whoever took it is holding it.
///
/// This is the pair that says what `RedoubtArray` is. It reads as a value that
/// would carry its bytes with it and does not: it holds a `Box<[T; N]>`, so a
/// move moves a pointer and the bytes stay where they were put. Take the `Box`
/// away and the test below starts finding the secret in the slot the value was
/// moved out of, with nobody left to empty it.
#[test]
fn test_a_redoubt_array_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        held.replace_from_mut_array(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "an array given away, and kept");

    core::hint::black_box(&source);

    Ok(())
}

/// Once whoever took it lets it go, nothing is left where it was.
#[test]
fn test_a_redoubt_array_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        held.replace_from_mut_array(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| let_go(held));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array given away");

    Ok(())
}

// ============================================================================
// RedoubtArray::drop
// ============================================================================

/// One that is dropped leaves nothing.
#[test]
fn test_a_redoubt_array_dropped_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtArray::<u8, 32>::default();
        held.replace_from_mut_array(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(held));
    });

    core::hint::black_box(&source);

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array dropped");

    Ok(())
}

// ============================================================================
// RedoubtOption::replace
// ============================================================================

/// A vec put inside an option is found while the option holds it.
#[test]
fn test_a_redoubt_option_replaced_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut inner = RedoubtVec::<u8>::new();
        inner.replace_from_mut_slice(&mut source);

        let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
        capture(|| held.replace(&mut inner));

        core::mem::forget(held);

        drop(inner);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an option replaced, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// An option filled at one size, and let go.
///
/// `replace` has to swap the value into place, which leaves a transit
/// temporary on the stack while it does — and that temporary is in the window
/// the capture copies.
macro_rules! a_redoubt_option_replaced {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut inner = RedoubtVec::<u8>::new();
                inner.replace_from_mut_slice(&mut source);

                let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
                capture(|| held.replace(&mut inner));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
                drop(inner);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an option replaced of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_32_leaves_nothing, 32);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_64_leaves_nothing, 64);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_128_leaves_nothing, 128);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_512_leaves_nothing, 512);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_1024_leaves_nothing, 1024);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_4096_leaves_nothing, 4096);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_8192_leaves_nothing, 8192);
a_redoubt_option_replaced!(
    test_a_redoubt_option_replaced_of_16384_leaves_nothing,
    16384
);
a_redoubt_option_replaced!(
    test_a_redoubt_option_replaced_of_32768_leaves_nothing,
    32768
);
a_redoubt_option_replaced!(
    test_a_redoubt_option_replaced_of_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtOption: ownership
// ============================================================================

/// An option given away is found while whoever took it is holding it.
#[test]
fn test_a_redoubt_option_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut inner = RedoubtVec::<u8>::new();
        inner.replace_from_mut_slice(&mut source);

        let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
        held.replace(&mut inner);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation. See the header.
        drop(inner);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an option given away, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// An option given away at one size.
///
/// One container deep: what is given away is the option, and what it holds is
/// a vec that is itself a pointer.
macro_rules! a_redoubt_option_given_away {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut inner = RedoubtVec::<u8>::new();
                inner.replace_from_mut_slice(&mut source);

                let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
                held.replace(&mut inner);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| let_go(held));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(inner);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an option given away of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_option_given_away!(test_a_redoubt_option_given_away_of_32_leaves_nothing, 32);
a_redoubt_option_given_away!(test_a_redoubt_option_given_away_of_64_leaves_nothing, 64);
a_redoubt_option_given_away!(test_a_redoubt_option_given_away_of_128_leaves_nothing, 128);
a_redoubt_option_given_away!(test_a_redoubt_option_given_away_of_512_leaves_nothing, 512);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_1024_leaves_nothing,
    1024
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_4096_leaves_nothing,
    4096
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_8192_leaves_nothing,
    8192
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_16384_leaves_nothing,
    16384
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_32768_leaves_nothing,
    32768
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtOption::drop
// ============================================================================

/// An option dropped at one size.
macro_rules! a_redoubt_option_dropped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut inner = RedoubtVec::<u8>::new();
                inner.replace_from_mut_slice(&mut source);

                let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
                held.replace(&mut inner);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| drop(held));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(inner);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an option dropped of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_32_leaves_nothing, 32);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_64_leaves_nothing, 64);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_128_leaves_nothing, 128);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_512_leaves_nothing, 512);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_1024_leaves_nothing, 1024);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_4096_leaves_nothing, 4096);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_8192_leaves_nothing, 8192);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_16384_leaves_nothing, 16384);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_32768_leaves_nothing, 32768);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_65536_leaves_nothing, 65536);

// ============================================================================
// RedoubtString::extend_from_mut_string
// ============================================================================

/// A string extended is found while the string holds it.
///
/// The needle here is the spelling and not the bytes: a string holds text, so
/// the secret has to be spelled to go into one.
#[test]
fn test_a_redoubt_string_extended_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let mut held = RedoubtString::new();
        capture(|| held.extend_from_mut_string(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string extended, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// A string extended to one size, and let go.
///
/// Appended rather than replaced, so the string reallocates on the way up
/// rather than being sized once. Each piece is its own `String`, handed over
/// and emptied by the call — which is what the `&mut` in the signature is for.
/// What the sweep asks about is the blocks the string outgrew on the way to
/// its final size.
macro_rules! a_redoubt_string_extended {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut sources: Vec<String> = (0..($of / (SECRET.len() * 2)).max(1))
                .map(|_| spelled(SECRET.len() * 2))
                .collect();

            forensics!({
                let mut held = RedoubtString::new();

                capture(|| {
                    for source in &mut sources {
                        held.extend_from_mut_string(source);
                    }
                });

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(sources));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string extended to {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_extended!(test_a_redoubt_string_extended_to_32_leaves_nothing, 32);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_64_leaves_nothing, 64);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_128_leaves_nothing, 128);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_512_leaves_nothing, 512);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_1024_leaves_nothing, 1024);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_4096_leaves_nothing, 4096);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_8192_leaves_nothing, 8192);
a_redoubt_string_extended!(
    test_a_redoubt_string_extended_to_16384_leaves_nothing,
    16384
);
a_redoubt_string_extended!(
    test_a_redoubt_string_extended_to_32768_leaves_nothing,
    32768
);
a_redoubt_string_extended!(
    test_a_redoubt_string_extended_to_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString::replace_from_mut_string
// ============================================================================

/// A string replaced is found while the string holds it.
#[test]
fn test_a_redoubt_string_replaced_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let mut held = RedoubtString::new();
        capture(|| held.replace_from_mut_string(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string replaced, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// A string replaced at one size, and let go.
///
/// The same question the vec is asked, of a second implementation: this type
/// has its own `grow_to` and reaches it the same way.
macro_rules! a_redoubt_string_replaced {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let mut held = RedoubtString::new();
                capture(|| held.replace_from_mut_string(&mut source));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string replaced of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_32_leaves_nothing, 32);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_64_leaves_nothing, 64);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_128_leaves_nothing, 128);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_512_leaves_nothing, 512);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_1024_leaves_nothing, 1024);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_4096_leaves_nothing, 4096);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_8192_leaves_nothing, 8192);
a_redoubt_string_replaced!(
    test_a_redoubt_string_replaced_of_16384_leaves_nothing,
    16384
);
a_redoubt_string_replaced!(
    test_a_redoubt_string_replaced_of_32768_leaves_nothing,
    32768
);
a_redoubt_string_replaced!(
    test_a_redoubt_string_replaced_of_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString::extend_from_str
// ============================================================================

/// A string extended from text it does not own is found while it holds it.
#[test]
fn test_a_redoubt_string_extended_from_a_str_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let mut held = RedoubtString::new();
        capture(|| held.extend_from_str(&source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string extended from a str, and kept");

    emptying(&mut source);

    drop(core::hint::black_box(source));

    Ok(())
}

/// A string extended from text it does not own, at one size.
///
/// The `&str` stays the caller's, so this is the only one of the three that
/// cannot empty what it was given — and it is the only one that reaches its
/// buffer through `push_str`, which is the `memcpy` the others are written to
/// avoid. What is measured is therefore narrower: whether the *string* kept a
/// copy, the caller's own text being the caller's to answer for.
///
/// Which is why the source is emptied by hand before the photograph rather
/// than left to its drop.
macro_rules! a_redoubt_string_extended_from_a_str {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let mut held = RedoubtString::new();
                capture(|| held.extend_from_str(&source));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            emptying(&mut source);

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string extended from a str of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_32_leaves_nothing,
    32
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_64_leaves_nothing,
    64
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_128_leaves_nothing,
    128
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_512_leaves_nothing,
    512
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_1024_leaves_nothing,
    1024
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_4096_leaves_nothing,
    4096
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_8192_leaves_nothing,
    8192
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_16384_leaves_nothing,
    16384
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_32768_leaves_nothing,
    32768
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString: ownership
// ============================================================================

/// A string given away is found while whoever took it is holding it.
#[test]
fn test_a_redoubt_string_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let mut held = RedoubtString::new();
        held.replace_from_mut_string(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string given away, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// A string given away at one size.
macro_rules! a_redoubt_string_given_away {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let mut held = RedoubtString::new();
                held.replace_from_mut_string(&mut source);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| let_go(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string of {} bytes given away", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_given_away!(test_a_redoubt_string_of_32_given_away_leaves_nothing, 32);
a_redoubt_string_given_away!(test_a_redoubt_string_of_64_given_away_leaves_nothing, 64);
a_redoubt_string_given_away!(test_a_redoubt_string_of_128_given_away_leaves_nothing, 128);
a_redoubt_string_given_away!(test_a_redoubt_string_of_512_given_away_leaves_nothing, 512);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_1024_given_away_leaves_nothing,
    1024
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_4096_given_away_leaves_nothing,
    4096
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_8192_given_away_leaves_nothing,
    8192
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_16384_given_away_leaves_nothing,
    16384
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_32768_given_away_leaves_nothing,
    32768
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_65536_given_away_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString::drop
// ============================================================================

/// A string dropped at one size.
macro_rules! a_redoubt_string_dropped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let mut held = RedoubtString::new();
                held.replace_from_mut_string(&mut source);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| drop(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string of {} bytes dropped", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_dropped!(test_a_redoubt_string_of_32_dropped_leaves_nothing, 32);
a_redoubt_string_dropped!(test_a_redoubt_string_of_64_dropped_leaves_nothing, 64);
a_redoubt_string_dropped!(test_a_redoubt_string_of_128_dropped_leaves_nothing, 128);
a_redoubt_string_dropped!(test_a_redoubt_string_of_512_dropped_leaves_nothing, 512);
a_redoubt_string_dropped!(test_a_redoubt_string_of_1024_dropped_leaves_nothing, 1024);
a_redoubt_string_dropped!(test_a_redoubt_string_of_4096_dropped_leaves_nothing, 4096);
a_redoubt_string_dropped!(test_a_redoubt_string_of_8192_dropped_leaves_nothing, 8192);
a_redoubt_string_dropped!(test_a_redoubt_string_of_16384_dropped_leaves_nothing, 16384);
a_redoubt_string_dropped!(test_a_redoubt_string_of_32768_dropped_leaves_nothing, 32768);
a_redoubt_string_dropped!(test_a_redoubt_string_of_65536_dropped_leaves_nothing, 65536);

// ============================================================================
// RedoubtVec::replace_from_mut_slice
// ============================================================================

/// A vec replaced is found while the vec holds it.
#[test]
fn test_a_redoubt_vec_replaced_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtVec::<u8>::new();
        capture(|| held.replace_from_mut_slice(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec replaced, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// A vec replaced at one size, and let go.
///
/// The vec grows to hold the slice, copies it in, zeroizes the source, and is
/// zeroized itself on the way out. Nothing of the secret is supposed to
/// outlive the call.
macro_rules! a_redoubt_vec_replaced {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut held = RedoubtVec::<u8>::new();
                capture(|| held.replace_from_mut_slice(&mut source));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec replaced of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_32_leaves_nothing, 32);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_64_leaves_nothing, 64);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_128_leaves_nothing, 128);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_512_leaves_nothing, 512);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_1024_leaves_nothing, 1024);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_4096_leaves_nothing, 4096);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_8192_leaves_nothing, 8192);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_16384_leaves_nothing, 16384);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_32768_leaves_nothing, 32768);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_65536_leaves_nothing, 65536);

// ============================================================================
// RedoubtVec::extend_from_mut_slice
// ============================================================================

/// A vec extended is found while the vec holds it.
#[test]
fn test_a_redoubt_vec_extended_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtVec::<u8>::new();
        capture(|| held.extend_from_mut_slice(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec extended, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// A vec extended to one size, and let go.
///
/// Appended rather than replaced, so the vec reallocates on the way up rather
/// than being sized once, and what the sweep asks about is the blocks it
/// outgrew.
macro_rules! a_redoubt_vec_extended {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut sources: Vec<Vec<u8>> = (0..($of / SECRET.len()).max(1))
                .map(|_| {
                    let mut source = vec![0_u8; SECRET.len()];

                    giving(&mut source);

                    source
                })
                .collect();

            forensics!({
                let mut held = RedoubtVec::<u8>::new();

                capture(|| {
                    for source in &mut sources {
                        held.extend_from_mut_slice(source);
                    }
                });

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(sources));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec extended to {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_32_leaves_nothing, 32);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_64_leaves_nothing, 64);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_128_leaves_nothing, 128);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_512_leaves_nothing, 512);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_1024_leaves_nothing, 1024);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_4096_leaves_nothing, 4096);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_8192_leaves_nothing, 8192);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_16384_leaves_nothing, 16384);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_32768_leaves_nothing, 32768);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_65536_leaves_nothing, 65536);

// ============================================================================
// RedoubtVec: ownership
// ============================================================================

/// A vec given away is found while whoever took it is holding it.
#[test]
fn test_a_redoubt_vec_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtVec::<u8>::new();
        held.replace_from_mut_slice(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec given away, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// A vec given away at one size.
///
/// The question an ownership section asks is not whether the drop empties the
/// value — the replaces ask that. It is whether *moving* it first changes the
/// answer, because a value that keeps its secret in its own bytes leaves the
/// slot it was moved out of with nobody to empty it.
///
/// What makes the answer no is one word in the declaration: the secret is
/// behind a `Box`, so what travels is the pointer and the bytes never move.
macro_rules! a_redoubt_vec_given_away {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut held = RedoubtVec::<u8>::new();
                held.replace_from_mut_slice(&mut source);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| let_go(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes given away", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_vec_given_away!(test_a_redoubt_vec_of_32_given_away_leaves_nothing, 32);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_64_given_away_leaves_nothing, 64);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_128_given_away_leaves_nothing, 128);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_512_given_away_leaves_nothing, 512);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_1024_given_away_leaves_nothing, 1024);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_4096_given_away_leaves_nothing, 4096);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_8192_given_away_leaves_nothing, 8192);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_16384_given_away_leaves_nothing, 16384);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_32768_given_away_leaves_nothing, 32768);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_65536_given_away_leaves_nothing, 65536);

// ============================================================================
// RedoubtVec::drop
// ============================================================================

/// A vec dropped at one size.
macro_rules! a_redoubt_vec_dropped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut held = RedoubtVec::<u8>::new();
                held.replace_from_mut_slice(&mut source);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| drop(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes dropped", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_vec_dropped!(test_a_redoubt_vec_of_32_dropped_leaves_nothing, 32);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_64_dropped_leaves_nothing, 64);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_128_dropped_leaves_nothing, 128);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_512_dropped_leaves_nothing, 512);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_1024_dropped_leaves_nothing, 1024);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_4096_dropped_leaves_nothing, 4096);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_8192_dropped_leaves_nothing, 8192);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_16384_dropped_leaves_nothing, 16384);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_32768_dropped_leaves_nothing, 32768);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_65536_dropped_leaves_nothing, 65536);
