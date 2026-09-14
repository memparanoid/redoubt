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
use redoubt_forensics::{AnyError, Forensics, QUIET, forensics};

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
fn leaves_nothing_at_any_size(what: &str, mut work: impl FnMut(usize)) -> Result<(), AnyError> {
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

/// A secret the value keeps in its own bytes, which is what none of the
/// containers here does.
///
/// Every one of them holds a `Box`, so moving one moves a pointer and the
/// secret stays where it was put. This one has nowhere else to be, so moving
/// it moves the bytes.
struct Inline {
    held: [u8; 32],
}

impl Inline {
    /// Taken by value, used, and the copy that was taken is emptied — which is
    /// the whole of what a value-consuming method can do. The slot it was
    /// copied *from* belongs to the caller and is not reachable from here, and
    /// a value that has been moved out of is one Rust emits no drop for.
    ///
    /// Not inlined, so that the move is one the machine makes. Folded into its
    /// caller there would be no second place for the bytes to be, and the
    /// control would measure the optimiser rather than the sweep.
    #[inline(never)]
    fn spend(mut self) {
        core::hint::black_box(&self.held);

        self.held = [0; 32];

        core::hint::black_box(&self.held);
    }
}

/// Takes the value and does not give it back.
///
/// What a caller handing one of these to somebody else is, and the thing the
/// ownership sections ask about: the value is moved, and whatever empties it
/// runs somewhere this test cannot see.
///
/// Not inlined. A move within one function is one the optimiser may fold away,
/// and a measurement of what a move leaves has to be sure a move happened.
#[inline(never)]
fn consume<T>(value: T) {
    core::hint::black_box(&value);
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

/// The sweep finds a secret in the slot a value was moved out of.
///
/// This is what makes every drop below worth reading. Those say that moving a
/// container and letting it go leaves nothing; that claim is empty unless the
/// sweep would have spoken had there been something, and a moved-from slot is
/// precisely the place it has to reach to say so.
///
/// It is also the net under a change nobody has made yet. Each container keeps
/// its secret behind a `Box` today, which is why moving one moves a pointer;
/// the day one of them holds its bytes inline, its drop test starts measuring
/// what this one measures, and this is what says the measurement works.
#[test]
fn test_the_sweep_finds_the_secret_a_move_left_behind() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = Inline { held: [0; 32] };

    giving(&mut source.held);

    // The move. What `spend` empties is the copy it was handed; `source` keeps
    // what that copy was made from, with nothing left to empty it.
    source.spend();

    let report_left_behind = watch.snapshot()?;

    println!();
    report_left_behind.summary("moved out of, and spent");
    println!();

    assert!(
        report_left_behind.found,
        "the sweep does not reach the slot a value was moved out of, so every \
         absence the drops below report is the instrument standing where the \
         evidence is: {report_left_behind}",
    );

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
fn test_replace_from_mut_slice_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
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
fn test_extend_from_mut_slice_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
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
// RedoubtVec: ownership
// ============================================================================

/// Given away, and emptied somewhere this test cannot see.
///
/// The question the ownership sections ask is not whether the drop empties the
/// value — the replaces ask that. It is whether *moving* it first changes the
/// answer, because a value that keeps its secret in its own bytes leaves the
/// slot it was moved out of with nobody to empty it.
///
/// What makes the answer no is one word in the declaration: the secret is
/// behind a `Box`, so what travels is the pointer and the bytes never move.
/// Whatever empties it reaches them at the address they were always at.
#[test]
fn test_a_vec_given_away_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("a vec given away", |of| {
        let mut source = vec![0_u8; of];

        giving(&mut source);

        let mut held = RedoubtVec::<u8>::new();

        held.replace_from_mut_slice(&mut source);

        consume(held);

        drop(core::hint::black_box(source));
    })
}

// ============================================================================
// RedoubtVec::drop
// ============================================================================

/// A vec that is never dropped is found.
///
/// The positive the test under it is worth nothing without. `forget` takes the
/// value and runs no destructor, so the secret stays in the block the vec had —
/// and if the sweep cannot see it there, then neither could it have seen it had
/// the drop failed to empty it, and the absence below would be the instrument
/// and not the code.
///
/// It leaks the allocation on purpose, which is what `forget` is for.
#[test]
fn test_a_vec_that_is_never_dropped_is_found() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    let mut held = RedoubtVec::<u8>::new();

    held.replace_from_mut_slice(&mut source);

    core::mem::forget(held);

    let report_never_emptied = watch.snapshot()?;

    println!();
    report_never_emptied.summary("a vec, never dropped");
    println!();

    assert!(
        report_never_emptied.found,
        "the sweep does not reach what a vec holds, so the absence the test \
         below reports is the instrument standing where the evidence is: \
         {report_never_emptied}",
    );

    drop(core::hint::black_box(source));

    Ok(())
}

/// And one that is dropped is not.
#[test]
fn test_a_vec_dropped_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("a vec dropped", |of| {
        let mut source = vec![0_u8; of];

        giving(&mut source);

        let mut held = RedoubtVec::<u8>::new();

        held.replace_from_mut_slice(&mut source);

        drop(held);

        drop(core::hint::black_box(source));
    })
}

// ============================================================================
// RedoubtString::extend_from_mut_string
// ============================================================================

/// Appended rather than replaced, so the string reallocates on the way up
/// rather than being sized once.
///
/// Each piece is its own `String`, handed over and emptied by the call — which
/// is what the `&mut` in the signature is for. What the sweep asks about is the
/// blocks the string outgrew on the way to its final size.
#[test]
fn test_string_extend_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing filled yet");

    for of in SIZES {
        let report_after = forensics!(watch, {
            let mut held = RedoubtString::new();

            for _ in 0..(of / (SECRET.len() * 2)).max(1) {
                let mut source = spelled(SECRET.len() * 2);

                held.extend_from_mut_string(&mut source);

                drop(core::hint::black_box(source));
            }

            drop(core::hint::black_box(held));
        });

        report_after.summary_against(&report_before, &format!("a string extended, {of} bytes"));

        assert!(
            !report_after.found,
            "the whole spelling survived a string extended to {of} bytes: \
             {report_after}"
        );

        assert!(
            report_after.widest <= QUIET,
            "a run of {} bytes survived a string extended to {of} bytes: \
             {report_after}",
            report_after.widest,
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "a string extended to {of} bytes moved the score: {delta}"
        );
    }

    println!();

    Ok(())
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
fn test_string_replace_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
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
// RedoubtString::extend_from_str
// ============================================================================

/// The one that is handed text it does not own.
///
/// The `&str` stays the caller's, so this is the only one of the three that
/// cannot empty what it was given — and it is the only one that reaches its
/// buffer through `push_str`, which is the `memcpy` the others are written to
/// avoid. What is measured is therefore narrower than above: whether the
/// *string* kept a copy, the caller's own text being the caller's to answer
/// for.
///
/// Which is why the source is emptied here before the photograph, a byte at a
/// time and volatile. A `String` does not clear itself when it is dropped, so
/// leaving that to the drop would find the spelling in the block the allocator
/// just took back and read it as this method's.
#[test]
fn test_string_extend_from_str_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing filled yet");

    for of in SIZES {
        let report_after = forensics!(watch, {
            let mut source = spelled(of);

            let mut held = RedoubtString::new();

            held.extend_from_str(&source);

            drop(core::hint::black_box(held));

            // SAFETY: every byte written is zero, which is valid UTF-8, and the
            // length is the string's own.
            let bytes = unsafe { source.as_mut_vec() };

            for at in 0..bytes.len() {
                // SAFETY: in bounds of a live vec.
                unsafe { bytes.as_mut_ptr().add(at).write_volatile(0) };
            }

            drop(core::hint::black_box(source));
        });

        report_after.summary_against(
            &report_before,
            &format!("a string extended from a str, {of} bytes"),
        );

        assert!(
            !report_after.found,
            "the whole spelling survived a string extended from a str of {of} \
             bytes: {report_after}"
        );

        assert!(
            report_after.widest <= QUIET,
            "a run of {} bytes survived a string extended from a str of {of} \
             bytes: {report_after}",
            report_after.widest,
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "a string extended from a str of {of} bytes moved the score: {delta}"
        );
    }

    println!();

    Ok(())
}

// ============================================================================
// RedoubtString: ownership
// ============================================================================

/// The same, for the type that holds text, which carries its own needle.
#[test]
fn test_a_string_given_away_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing filled yet");

    for of in SIZES {
        let report_after = forensics!(watch, {
            let mut source = spelled(of);

            let mut held = RedoubtString::new();

            held.replace_from_mut_string(&mut source);

            consume(held);

            drop(core::hint::black_box(source));
        });

        report_after.summary_against(&report_before, &format!("a string given away, {of} bytes"));

        assert!(
            !report_after.found,
            "the whole spelling survived a string of {of} bytes being given \
             away: {report_after}"
        );

        assert!(
            report_after.widest <= QUIET,
            "a run of {} bytes survived a string of {of} bytes being given \
             away: {report_after}",
            report_after.widest,
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "a string of {of} bytes given away moved the score: {delta}"
        );
    }

    println!();

    Ok(())
}

// ============================================================================
// RedoubtString::drop
// ============================================================================

/// A string that is never dropped is found.
#[test]
fn test_a_string_that_is_never_dropped_is_found() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    let mut held = RedoubtString::new();

    held.replace_from_mut_string(&mut source);

    core::mem::forget(held);

    let report_never_emptied = watch.snapshot()?;

    println!();
    report_never_emptied.summary("a string, never dropped");
    println!();

    assert!(
        report_never_emptied.found,
        "the sweep does not reach what a string holds, so the absence the test \
         below reports is the instrument standing where the evidence is: \
         {report_never_emptied}",
    );

    drop(core::hint::black_box(source));

    Ok(())
}

/// And one that is dropped is not.
#[test]
fn test_a_string_dropped_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing filled yet");

    for of in SIZES {
        let report_after = forensics!(watch, {
            let mut source = spelled(of);

            let mut held = RedoubtString::new();

            held.replace_from_mut_string(&mut source);

            drop(held);

            drop(core::hint::black_box(source));
        });

        report_after.summary_against(&report_before, &format!("a string dropped, {of} bytes"));

        assert!(
            !report_after.found,
            "the whole spelling survived a string of {of} bytes being dropped: \
             {report_after}"
        );

        assert!(
            report_after.widest <= QUIET,
            "a run of {} bytes survived a string of {of} bytes being dropped: \
             {report_after}",
            report_after.widest,
        );

        let delta = report_after.against(&report_before);

        assert!(
            delta.is_noise(),
            "a string of {of} bytes dropped moved the score: {delta}"
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
fn test_option_replace_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
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
// RedoubtOption: ownership
// ============================================================================

/// The same, one container deep: what is given away is the option, and what it
/// holds is a vec that is itself a pointer.
#[test]
fn test_an_option_given_away_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("an option given away", |of| {
        let mut source = vec![0_u8; of];

        giving(&mut source);

        let mut inner = RedoubtVec::<u8>::new();

        inner.replace_from_mut_slice(&mut source);

        let mut held = RedoubtOption::<RedoubtVec<u8>>::default();

        held.replace(&mut inner);

        consume(held);

        drop(core::hint::black_box(inner));
        drop(core::hint::black_box(source));
    })
}

// ============================================================================
// RedoubtOption::drop
// ============================================================================

/// An option that is never dropped is found.
#[test]
fn test_an_option_that_is_never_dropped_is_found() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    let mut inner = RedoubtVec::<u8>::new();

    inner.replace_from_mut_slice(&mut source);

    let mut held = RedoubtOption::<RedoubtVec<u8>>::default();

    held.replace(&mut inner);

    core::mem::forget(held);

    let report_never_emptied = watch.snapshot()?;

    println!();
    report_never_emptied.summary("an option, never dropped");
    println!();

    assert!(
        report_never_emptied.found,
        "the sweep does not reach what an option holds, so the absence the test \
         below reports is the instrument standing where the evidence is: \
         {report_never_emptied}",
    );

    drop(core::hint::black_box(inner));
    drop(core::hint::black_box(source));

    Ok(())
}

/// And one that is dropped is not.
#[test]
fn test_an_option_dropped_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing_at_any_size("an option dropped", |of| {
        let mut source = vec![0_u8; of];

        giving(&mut source);

        let mut inner = RedoubtVec::<u8>::new();

        inner.replace_from_mut_slice(&mut source);

        let mut held = RedoubtOption::<RedoubtVec<u8>>::default();

        held.replace(&mut inner);

        drop(held);

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
fn test_array_replace_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
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

// ============================================================================
// RedoubtArray: ownership
// ============================================================================

/// The same, for the one whose length is in its type.
///
/// This is the one the moved-from control is aimed at. `RedoubtArray` reads as
/// a value that would carry its bytes with it and does not: it holds a
/// `Box<[T; N]>`, and that is the whole of why this passes. Take the `Box` away
/// and this measures what that control measures.
#[test]
fn test_an_array_given_away_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let report_after = forensics!(watch, {
        let mut source = [0_u8; 32];

        giving(&mut source);

        let mut held = RedoubtArray::<u8, 32>::default();

        held.replace_from_mut_array(&mut source);

        // By reference, for the reason the replace test gives: `[u8; 32]` is
        // `Copy`, and a `black_box` of it by value is one more copy.
        core::hint::black_box(&source);

        consume(held);
    });

    println!();
    report_before.summary("nothing filled yet");
    report_after.summary_against(&report_before, "an array given away");
    println!();

    assert!(
        !report_after.found,
        "the whole secret survived an array being given away: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived an array being given away: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(&report_before);

    assert!(
        delta.is_noise(),
        "an array given away moved the score: {delta}"
    );

    Ok(())
}

// ============================================================================
// RedoubtArray::drop
// ============================================================================

/// An array that is never dropped is found.
#[test]
fn test_an_array_that_is_never_dropped_is_found() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = [0_u8; 32];

    giving(&mut source);

    let mut held = RedoubtArray::<u8, 32>::default();

    held.replace_from_mut_array(&mut source);

    core::mem::forget(held);

    let report_never_emptied = watch.snapshot()?;

    println!();
    report_never_emptied.summary("an array, never dropped");
    println!();

    assert!(
        report_never_emptied.found,
        "the sweep does not reach what an array holds, so the absence the test \
         below reports is the instrument standing where the evidence is: \
         {report_never_emptied}",
    );

    core::hint::black_box(&source);

    Ok(())
}

/// And one that is dropped is not.
#[test]
fn test_an_array_dropped_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let report_after = forensics!(watch, {
        let mut source = [0_u8; 32];

        giving(&mut source);

        let mut held = RedoubtArray::<u8, 32>::default();

        held.replace_from_mut_array(&mut source);

        core::hint::black_box(&source);

        drop(held);
    });

    println!();
    report_before.summary("nothing filled yet");
    report_after.summary_against(&report_before, "an array dropped");
    println!();

    assert!(
        !report_after.found,
        "the whole secret survived an array being dropped: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived an array being dropped: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(&report_before);

    assert!(
        delta.is_noise(),
        "an array dropped moved the score: {delta}"
    );

    Ok(())
}
