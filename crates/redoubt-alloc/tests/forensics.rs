// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a container leaves behind once it has been filled and dropped.
//!
//! # Why size is the axis
//!
//! A container that leaks a secret of thirty-two bytes and not one of thirty
//! kilobytes would be a strange thing. The other way round is not strange at
//! all: a large buffer is reallocated on the way up, is copied through a
//! routine that takes a different path by length, and puts enough pressure on
//! the register allocator that the compiler starts spilling to stack slots
//! nobody clears.
//!
//! So every measurement here is a sweep over sizes, and a leak that shows at
//! one size and not another says which of those it is.
//!
//! # The destination is dropped
//!
//! A container still holding the secret would be found, and would say
//! nothing. Each one is dropped before the photograph, so what is left was
//! not in any container when the operation ended.

#![cfg(target_os = "linux")]

use redoubt_alloc::{RedoubtArray, RedoubtOption, RedoubtString, RedoubtVec};
use redoubt_forensics::{Forensics, QUIET, Reason, forensics};

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
const SIZES: [usize; 10] = [32, 64, 128, 512, 1024, 4096, 8192, 16384, 32768, 65536];

/// The needle, built from its last byte to its first.
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

const HEX: [u8; 16] = *b"0123456789abcdef";

/// The secret written out as hex, over and over, as a `String`.
///
/// A string holds text, so the secret has to be spelled to go into one, and
/// what the sweep looks for there is the spelling rather than the bytes.
///
/// Written one character at a time into room reserved up front. Neither
/// `push_str` nor `write!` would do: both are `memcpy`, and the string would
/// grow under them and leave the spelling in every block it outgrew — which
/// is the very thing being measured, caused by the measuring.
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

/// Everything a caller must be able to say about what an operation left, at
/// every size.
fn leaves_nothing_at_any_size(what: &str, mut work: impl FnMut(usize)) -> Result<(), Reason> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing filled yet");

    for of in SIZES {
        let report_after = forensics!(watch, { work(of) });

        report_after.summary_against(&report_before, &format!("{what}, {of} bytes"));

        assert!(
            !report_after.found,
            "the whole secret survived {what} of {of} bytes: {report_after}",
        );

        assert!(
            report_after.widest <= QUIET,
            "a run of {} bytes survived {what} of {of} bytes, and {QUIET} is what \
             memory has by accident: {report_after}",
            report_after.widest,
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "{what} of {of} bytes moved the score: {delta}"
        );
    }

    println!();

    Ok(())
}

// ============================================================================
// The control
// ============================================================================

/// The sweep finds the secret when the secret is plainly there.
///
/// A test of its own, so the copy it plants is in nobody else's memory.
#[test]
fn test_the_sweep_finds_the_secret_while_it_is_held() -> Result<(), Reason> {
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
// RedoubtVec::replace_from_mut_slice
// ============================================================================

/// Filled, and then dropped.
///
/// The vec grows to hold the slice, copies it in, zeroizes the source, and is
/// zeroized itself on the way out. Nothing of the secret is supposed to
/// outlive the call.
#[test]
fn test_replace_from_mut_slice_leaves_nothing_a_sweep_can_find() -> Result<(), Reason> {
    leaves_nothing_at_any_size("a vec replaced", |of| {
        let mut source = vec![0_u8; of];

        giving(&mut source);

        let mut held = RedoubtVec::<u8>::new();

        held.replace_from_mut_slice(&mut source);

        drop(core::hint::black_box(held));
        drop(core::hint::black_box(source));
    })
}

// ============================================================================
// RedoubtVec::extend_from_mut_slice
// ============================================================================

/// The same, appended rather than replaced, so the vec reallocates on the way
/// up rather than being sized once.
#[test]
fn test_extend_from_mut_slice_leaves_nothing_a_sweep_can_find() -> Result<(), Reason> {
    leaves_nothing_at_any_size("a vec extended", |of| {
        let mut held = RedoubtVec::<u8>::new();

        for _ in 0..(of / SECRET.len()).max(1) {
            let mut source = vec![0_u8; SECRET.len()];

            giving(&mut source);
            held.extend_from_mut_slice(&mut source);

            drop(core::hint::black_box(source));
        }

        drop(core::hint::black_box(held));
    })
}

// ============================================================================
// RedoubtString::replace_from_mut_string
// ============================================================================

/// The same as the vec, for the type that holds text.
///
/// It has its own `grow_to` and reaches it the same way, so it is the same
/// question asked of a second implementation rather than a second question.
///
/// The secret is written as hex digits: the bytes that land in the string are
/// not the bytes of [`SECRET`], so this test carries its own needle.
#[test]
fn test_string_replace_leaves_nothing_a_sweep_can_find() -> Result<(), Reason> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing filled yet");

    for of in SIZES {
        let report_after = forensics!(watch, {
            let mut source = spelled(of);

            let mut held = RedoubtString::new();

            held.replace_from_mut_string(&mut source);

            drop(core::hint::black_box(held));
            drop(core::hint::black_box(source));
        });

        report_after.summary_against(&report_before, &format!("a string replaced, {of} bytes"));

        assert!(
            !report_after.found,
            "the whole secret survived a string of {of} bytes: {report_after}"
        );

        assert!(
            report_after.widest <= QUIET,
            "a run of {} bytes survived a string of {of} bytes: {report_after}",
            report_after.widest,
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "a string of {of} bytes moved the score: {delta}"
        );
    }

    println!();

    Ok(())
}

// ============================================================================
// RedoubtOption::replace
// ============================================================================

/// A vec put inside an option, which has to swap the value into place and
/// leaves a transit temporary on the stack while it does.
#[test]
fn test_option_replace_leaves_nothing_a_sweep_can_find() -> Result<(), Reason> {
    leaves_nothing_at_any_size("an option replaced", |of| {
        let mut source = vec![0_u8; of];

        giving(&mut source);

        let mut inner = RedoubtVec::<u8>::new();

        inner.replace_from_mut_slice(&mut source);

        let mut held = RedoubtOption::<RedoubtVec<u8>>::default();

        held.replace(&mut inner);

        drop(core::hint::black_box(held));
        drop(core::hint::black_box(inner));
        drop(core::hint::black_box(source));
    })
}

// ============================================================================
// RedoubtArray::replace_from_mut_array
// ============================================================================

/// An array, whose size is fixed, so the sweep over sizes has nothing to say
/// here and one size is the whole of it.
#[test]
fn test_array_replace_leaves_nothing_a_sweep_can_find() -> Result<(), Reason> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let report_after = forensics!(watch, {
        let mut source = [0_u8; 32];

        giving(&mut source);

        let mut held = RedoubtArray::<u8, 32>::default();

        held.replace_from_mut_array(&mut source);

        // By reference on purpose: `[u8; 32]` is `Copy`, so a `black_box` of
        // it by value makes one more copy on the stack, and the test would be
        // measuring itself.
        core::hint::black_box(&source);

        drop(core::hint::black_box(held));
    });

    println!();
    report_before.summary("nothing filled yet");
    report_after.summary_against(&report_before, "an array replaced");
    println!();

    assert!(
        !report_after.found,
        "the whole secret survived an array replace: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived an array replace: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(&report_before);

    assert!(
        delta.is_noise(),
        "an array replace moved the score: {delta}"
    );

    Ok(())
}
