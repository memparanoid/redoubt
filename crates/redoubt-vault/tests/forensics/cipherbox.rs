// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each way of opening a cipherbox leaves behind.
//!
//! # One secret, four shapes
//!
//! The same thirty-two bytes go into a `RedoubtVec`, a `RedoubtArray`, an
//! option around a vec and an option around an option around an array. One
//! needle then covers all four, and a photograph that finds nothing found
//! nothing in any of them.
//!
//! The shapes are not decoration. A vec keeps its bytes in a heap block it
//! reallocates, an array in a box it never moves, and an option has to take
//! its value out and put it back — three different paths for the same bytes,
//! and the one thing they have in common is that the ciphertext is the only
//! place either is supposed to rest.
//!
//! # An absolute bound, and then a difference
//!
//! Every photograph is held to [`QUIET`] — the widest run memory throws up by
//! accident — and that bound owes nothing to any other photograph. A residue
//! that vanishes while another appears reads as no change at all, so a
//! difference alone would not catch it.
//!
//! The differences come after, and say what each operation moved.
//!
//! # The control is a test of its own
//!
//! A sweep that reaches nowhere answers `no` to everything, exactly like a
//! process that is clean. Only a copy the sweep has to find tells the two
//! apart, and `nextest` gives each test a process, so the copy is planted in
//! a process where nothing else is being measured.

use redoubt_alloc::{RedoubtArray, RedoubtOption, RedoubtVec};
use redoubt_codec::RedoubtCodec;
use redoubt_forensics::{AnyError, Forensics, QUIET, forensics};
use redoubt_vault::{CipherBoxError, cipherbox};
use redoubt_zero::RedoubtZero;

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives where nothing can write and the sweep never reads it
/// as a copy.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// One round leaving nothing is a weaker claim than it looks.
///
/// A piece surviving one round in fifty would not show once and would show
/// plainly at two hundred.
const ROUNDS: usize = 200;

/// How many times the secret goes into the containers that can hold more than
/// one of it.
///
/// Thirty-two kilobytes, which is large enough that every buffer on the way
/// into the ciphertext has to be that large too.
const TIMES: usize = 1024;

#[cipherbox(SecretBox)]
#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct Secret {
    in_a_vec: RedoubtVec<u8>,
    in_an_array: RedoubtArray<u8, 32>,
    in_an_option: RedoubtOption<RedoubtVec<u8>>,
    in_two_options: RedoubtOption<RedoubtOption<RedoubtArray<u8, 32>>>,
}

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

/// The secret into somewhere the caller already owns, by the copy that erases
/// what it used.
///
/// Not `let mut source = SECRET`, and not `SECRET.to_vec()`. Both are whatever
/// move the compiler emits, and for thirty-two bytes that is vector registers
/// nobody clears — so the test would leak on the way in and every number below
/// would be about the test rather than the box.
///
/// Filled in place and not returned, because a thirty-two byte return value is
/// one more move.
fn giving(into: &mut [u8]) {
    // SAFETY: every caller below passes at least as many bytes as the secret
    // has, and a constant and a local are different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), into.as_mut_ptr(), SECRET.len()) };
}

/// The secret into all four shapes, out of locals that are cleared behind it.
///
/// This is the operation the rest of the file measures the aftermath of:
/// wherever the plaintext moves on its way into the ciphertext, it moves here.
fn seal(into: &mut SecretBox) -> Result<(), CipherBoxError> {
    into.open_mut(|it| {
        let mut source = [0_u8; 32];

        giving(&mut source);
        it.in_an_array.replace_from_mut_array(&mut source);

        // Replaced and not extended: extending appends, so sealing twice
        // would leave one more copy of the secret per round by the test's own
        // doing.
        let mut source = vec![0_u8; SECRET.len() * TIMES];

        for one in source.chunks_mut(SECRET.len()) {
            giving(one);
        }

        it.in_a_vec.replace_from_mut_slice(&mut source);

        // Room asked for up front, so the extend below never reaches
        // `grow_to`. A payload this size with no growth in it is what tells a
        // leak in the growing apart from a leak in everything else that has
        // to carry thirty-two kilobytes.
        let mut inner = RedoubtVec::<u8>::with_capacity(SECRET.len() * TIMES);
        let mut source = vec![0_u8; SECRET.len() * TIMES];

        for one in source.chunks_mut(SECRET.len()) {
            giving(one);
        }

        inner.replace_from_mut_slice(&mut source);
        it.in_an_option.replace(&mut inner);

        let mut source = [0_u8; 32];
        let mut inner = RedoubtArray::<u8, 32>::default();

        giving(&mut source);
        inner.replace_from_mut_array(&mut source);

        let mut wrapped = RedoubtOption::<RedoubtArray<u8, 32>>::default();

        wrapped.replace(&mut inner);
        it.in_two_options.replace(&mut wrapped);

        Ok(())
    })?;

    Ok(())
}

/// A box with the secret already in it, and the instrument watching.
///
/// Sealing happens before the first photograph on purpose: what every test but
/// one below asks about is what *opening* leaves, and sealing's own leavings
/// would otherwise sit in the difference.
fn sealed() -> Result<(SecretBox, Forensics), AnyError> {
    let watch = Forensics::watching(&backwards())?;
    let mut box_ = SecretBox::new();

    seal(&mut box_)?;

    Ok((box_, watch))
}

/// Everything a caller must be able to say about what an operation left.
///
/// The absolute bound first and on both photographs, then the difference. The
/// operation runs [`ROUNDS`] times, because a piece that survives one round in
/// fifty would not show once.
fn leaves_nothing(
    what: &str,
    mut work: impl FnMut(&mut SecretBox) -> Result<(), CipherBoxError>,
) -> Result<(), AnyError> {
    let (mut box_, mut watch) = sealed()?;

    let report_before = watch.snapshot()?;

    // The error is named because nothing else here does: the block is written
    // in place rather than passed as a closure with a declared signature, so
    // `?` on a `CipherBoxError` leaves the type of what comes out open.
    let report_after = forensics!(watch, {
        for _ in 0..ROUNDS {
            work(&mut box_)?;
        }

        Ok::<(), AnyError>(())
    });

    println!();
    report_before.summary("sealed, nothing opened");
    report_after.summary_against(&report_before, what);
    println!();

    for (when, report) in [("sealing", &report_before), (what, &report_after)] {
        assert!(
            !report.found,
            "the whole secret was left behind by {when}: {report}"
        );

        assert!(
            report.widest <= QUIET,
            "a run of {} bytes of the secret was left behind by {when}, and {QUIET} is \
             what memory has by accident: {report}",
            report.widest,
        );
    }

    let delta = report_after.against(&report_before);

    assert!(
        delta.is_noise(),
        "{what} moved the score past chance: {delta}"
    );

    drop(core::hint::black_box(box_));

    Ok(())
}

// ============================================================================
// The control
// ============================================================================

/// The sweep finds the secret when the secret is plainly there.
///
/// Every zero this file reports is worth exactly what this test is worth. It
/// is a test of its own so that the copy it plants is in nobody else's memory.
#[test]
fn test_the_sweep_finds_the_secret_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let held = core::hint::black_box(SECRET.to_vec());

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
// Sealing
// ============================================================================

/// Putting the secret in leaves nothing behind, which every other test here
/// takes for granted.
///
/// Once and then many times, as two tests, because they fail for different
/// reasons. One round failing is a leak in a single seal. Only the many-round
/// one failing is something that accumulates — a residue that survives one
/// round in fifty, or a container that grows and leaves its old contents
/// behind on the way.
fn sealing_leaves_nothing(rounds: usize) -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut box_ = SecretBox::new();

    let report_after = forensics!(watch, {
        for _ in 0..rounds {
            seal(&mut box_)?;
        }

        Ok::<(), AnyError>(())
    });

    println!();
    report_before.summary("nothing sealed yet");
    report_after.summary_against(&report_before, &format!("sealed {rounds} times"));
    println!();

    assert!(
        !report_after.found,
        "the whole secret survived sealing: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived sealing, and {QUIET} is what memory has by \
         accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(&report_before);

    assert!(
        delta.is_noise(),
        "sealing moved the score past chance: {delta}"
    );

    drop(core::hint::black_box(box_));

    Ok(())
}

#[test]
fn test_sealing_once_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    sealing_leaves_nothing(1)
}

#[test]
fn test_sealing_many_times_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    sealing_leaves_nothing(ROUNDS)
}

// ============================================================================
// open
// ============================================================================

/// Reading the whole struct, which decrypts all four shapes at once.
#[test]
fn test_open_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing("opened whole", |box_| {
        box_.open(|it| {
            core::hint::black_box(it.in_an_array.as_slice()[0]);

            Ok(())
        })?;

        Ok(())
    })
}

// ============================================================================
// open_mut
// ============================================================================

/// The same, and written back — so the plaintext makes the return trip as
/// well.
#[test]
fn test_open_mut_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing("opened whole for writing", |box_| {
        box_.open_mut(|it| {
            it.in_an_array.as_mut_slice()[0] ^= 0;

            Ok(())
        })?;

        Ok(())
    })
}

// ============================================================================
// open_<field>
// ============================================================================

/// One field, through the option that has to take its value out and put it
/// back twice over.
#[test]
fn test_open_field_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing("opened one field", |box_| {
        box_.open_in_two_options(|it| {
            core::hint::black_box(it.as_ref().is_ok());

            Ok(())
        })?;

        Ok(())
    })
}

// ============================================================================
// open_<field>_mut
// ============================================================================

#[test]
fn test_open_field_mut_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing("opened one field for writing", |box_| {
        box_.open_in_two_options_mut(|it| {
            core::hint::black_box(it.as_ref().is_ok());

            Ok(())
        })?;

        Ok(())
    })
}

// ============================================================================
// leak_<field> — one per shape
// ============================================================================

/// A vec, whose bytes live in a heap block it reallocates.
#[test]
fn test_leak_a_vec_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing("leaked a vec", |box_| {
        let taken = box_.leak_in_a_vec()?;

        core::hint::black_box(taken.as_slice()[0]);

        Ok(())
    })
}

/// An array, whose bytes live in a box that never moves.
#[test]
fn test_leak_an_array_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing("leaked an array", |box_| {
        let taken = box_.leak_in_an_array()?;

        core::hint::black_box(taken.as_slice()[0]);

        Ok(())
    })
}

/// An option around a vec, which has to take the value out and put it back.
#[test]
fn test_leak_an_option_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing("leaked an option", |box_| {
        let taken = box_.leak_in_an_option()?;

        core::hint::black_box(taken.as_ref().is_ok());

        Ok(())
    })
}

/// And an option around an option, which does it twice.
#[test]
fn test_leak_two_options_leaves_nothing_a_sweep_can_find() -> Result<(), AnyError> {
    leaves_nothing("leaked two options", |box_| {
        let taken = box_.leak_in_two_options()?;

        core::hint::black_box(taken.as_ref().is_ok());

        Ok(())
    })
}
