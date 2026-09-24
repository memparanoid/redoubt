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
//! reallocates, an array in a box it never moves, and an option has to take its
//! value out and put it back — three different paths for the same bytes, and
//! the one thing they have in common is that the ciphertext is the only place
//! either is supposed to rest.
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
//! # Nothing is dropped here, and the controls are photographed in odd places
//!
//! A cipherbox holds ciphertext at rest, so there is no legitimate copy of the
//! plaintext to remove before a photograph and no drop to measure: letting the
//! box go destroys ciphertext, which is not what any of this is about.
//!
//! What that costs is the usual place to put a control. An `open` finishes —
//! by the time it returns the plaintext is gone — so its control is
//! photographed **from inside the closure**, which is the only moment the
//! plaintext exists to be found. A `leak` hands it back, so its control holds
//! what it was handed.
//!
//! Neither plants anything. A copy the test put somewhere of its own choosing
//! would vouch for that place and not for the one the operation uses.

use redoubt_alloc::{RedoubtArray, RedoubtOption, RedoubtVec};
use redoubt_codec::RedoubtCodec;
use redoubt_forensics::{AnyError, Forensics, QUIET, Reason, Report, capture, forensics};
use redoubt_vault::{CipherBoxError, cipherbox};
use redoubt_zero::RedoubtZero;

use crate::support::needles::{SECRET, backwards};
use crate::support::{giving, is_found, leaves_nothing};

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

#[cipherbox(SecretsBox)]
#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct Secret {
    a_vec: RedoubtVec<u8>,
    an_array: RedoubtArray<u8, 32>,
    an_option: RedoubtOption<RedoubtVec<u8>>,
    two_options: RedoubtOption<RedoubtOption<RedoubtArray<u8, 32>>>,
}

/// The secret into all four shapes, out of locals that are cleared behind it.
///
/// This is the operation the rest of the file measures the aftermath of:
/// wherever the plaintext moves on its way into the ciphertext, it moves here.
fn open_fill_and_close(into: &mut SecretsBox) -> Result<(), CipherBoxError> {
    into.open_mut(|it| {
        let mut source = [0_u8; 32];

        giving(&mut source);
        it.an_array.replace_from_mut_array(&mut source);

        // Replaced and not extended: extending appends, so filling twice would
        // leave one more copy of the secret per round by the test's own doing.
        let mut source = vec![0_u8; SECRET.len() * TIMES];

        giving(&mut source);

        it.a_vec.replace_from_mut_slice(&mut source);

        // Room asked for up front, so the extend below never reaches `grow_to`.
        // A payload this size with no growth in it is what tells a leak in the
        // growing apart from a leak in everything else that has to carry
        // thirty-two kilobytes.
        let mut inner = RedoubtVec::<u8>::with_capacity(SECRET.len() * TIMES);
        let mut source = vec![0_u8; SECRET.len() * TIMES];

        giving(&mut source);

        inner.replace_from_mut_slice(&mut source);
        it.an_option.replace(&mut inner);

        let mut source = [0_u8; 32];
        let mut inner = RedoubtArray::<u8, 32>::default();

        giving(&mut source);
        inner.replace_from_mut_array(&mut source);

        let mut wrapped = RedoubtOption::<RedoubtArray<u8, 32>>::default();

        wrapped.replace(&mut inner);
        it.two_options.replace(&mut wrapped);

        Ok(())
    })?;

    Ok(())
}

/// A box with the secret already in it, the instrument watching, and the
/// photograph that says filling it left nothing.
///
/// The filling happens before the first photograph on purpose: what every test
/// taking this asks about is what *opening* leaves, and the filling's own
/// leavings would otherwise sit in the difference. The two tests that ask about
/// the filling itself do not take this — they watch it happen.
///
/// Which is why that photograph is held to the bound here rather than in each
/// test: it is the same precondition every one of them starts from, and a test
/// that measured an open against a dirty start would be reading a difference
/// from a number that already had the secret in it.
fn filled() -> Result<(SecretsBox, Forensics, Report), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;
    let mut secrets_box = SecretsBox::new();

    open_fill_and_close(&mut secrets_box)?;

    let report_before = watch.snapshot()?;

    assert!(
        !report_before.found,
        "the whole secret was left behind by filling the box: {report_before}"
    );

    assert!(
        report_before.widest <= QUIET,
        "a run of {} bytes of the secret was left behind by filling the box, and \
         {QUIET} is what memory has by accident: {report_before}",
        report_before.widest,
    );

    Ok((secrets_box, watch, report_before))
}

/// Takes the box and lets it go, which runs its drop somewhere this test
/// cannot see.
///
/// What handing one of these to somebody else is. Not inlined: a move within
/// one function is one the optimiser may fold away, and a measurement of what
/// a move leaves has to be sure a move happened.
#[inline(never)]
fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

// ============================================================================
// SecretsBox::drop
// ============================================================================

#[test]
fn test_a_box_dropped_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| drop(secrets_box));
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "a box dropped",
    );

    Ok(())
}

// ============================================================================
// SecretsBox: ownership
// ============================================================================

/// A box given away and let go leaves nothing behind.
///
/// What this asks is whether *moving* the box first changes the answer. It
/// does not, and for the same reason the containers underneath pass: what
/// travels is pointers, and the buffers never move. A box that carried them
/// inline would leave a copy of each in the slot it was moved out of, with
/// nothing left to empty them.
#[test]
fn test_a_box_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut secrets_box = SecretsBox::new();

    forensics!({
        open_fill_and_close(&mut secrets_box)?;

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether the move itself leaves a copy in the
        // registers or the stack it used. What it writes over is whatever ran
        // before it, which has a section of its own.
        capture(|| let_go(secrets_box));
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing filled yet",
        &report_after,
        "a box given away",
    );

    Ok(())
}

// ============================================================================
// SecretsBox: at rest
// ============================================================================

/// A box that has been filled and left alone holds nothing a sweep can find.
///
/// The at-rest claim, and the one everything else here quietly stands on:
/// between calls, what is in memory is ciphertext. Nothing is dropped and
/// nothing is opened — the box is alive and full when the photograph is taken,
/// which is the state it spends its life in.
///
/// Its pair is the control in the `open` section. The same box, the same
/// process, and the only difference is whether it is open: open, the whole
/// secret is there; closed, none of it is.
#[test]
fn test_a_filled_box_holds_nothing_at_rest() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut secrets_box = SecretsBox::new();

    forensics!({
        capture(|| open_fill_and_close(&mut secrets_box))?;
    });

    // Held across the photograph, and by reference so that holding it is not
    // one more copy. Let go before it, the measurement would be about the drop
    // instead of about what the box keeps.
    core::hint::black_box(&secrets_box);

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing filled yet",
        &report_after,
        "a filled box, at rest",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty box."]
fn test_making_a_box_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// SecretsBox::open
// ============================================================================

/// The secret is found while the box is open.
///
/// Taking a photograph forks and writes over a good deal of stack, which costs
/// nothing to a test asserting a presence: a disturbed measurement can lose the
/// secret and turn this red, and cannot invent one.
#[test]
fn test_the_secret_is_found_while_the_box_is_open() -> Result<(), AnyError> {
    let (secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while the box is open");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

/// Reading the whole struct, which decrypts all four shapes at once.
#[test]
fn test_open_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open(|it| {
                    core::hint::black_box(it.an_array.as_slice()[0]);

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened whole",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed = secrets_box.open(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened whole, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::open_mut
// ============================================================================

/// The secret is found while the box is open for writing.
///
/// The photograph is taken from inside the closure, where the plaintext is
/// decrypted and alive in the buffers the call made for it. `open_mut` writes
/// the value back as well, so what it holds open is not what the read-only
/// call holds open, and an absence measured against one does not vouch for the
/// other.
#[test]
fn test_the_secret_is_found_while_the_box_is_open_for_writing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open_mut(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while the box is open for writing");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

/// Reading the whole struct and writing it back, so the plaintext makes the
/// return trip as well.
#[test]
fn test_open_mut_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open_mut(|it| {
                    it.an_array.as_mut_slice()[0] ^= 0;

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened whole for writing",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

/// An `open_mut` with something to write, which is what fills the box.
///
/// The closures above read a byte and hand it back; this one replaces every
/// field, so the plaintext makes the whole trip in — through the containers,
/// the encoding and the cipher — inside one `open_mut`. If any of that keeps a
/// copy, the boxes every other test here starts from were dirty before they
/// were measured.
#[test]
fn test_filling_every_field_once_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut secrets_box = SecretsBox::new();

    forensics!({
        capture(|| open_fill_and_close(&mut secrets_box))?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing filled yet",
        &report_after,
        "filled once",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

/// Filling it many times leaves nothing either.
///
/// Its own test rather than one more round in the one above, because the two
/// fail for different reasons. One round failing is a leak in a single fill.
/// Only this one failing is something that accumulates — a residue that
/// survives one round in fifty, or a container that grows and leaves its old
/// contents behind on the way.
#[test]
fn test_filling_every_field_many_times_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut secrets_box = SecretsBox::new();

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                open_fill_and_close(&mut secrets_box)?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing filled yet",
        &report_after,
        &format!("filled {ROUNDS} times"),
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_mut_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed = secrets_box.open_mut(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened whole for writing, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::leak_a_vec
// ============================================================================

/// What a leak handed back is found while whoever asked for it is holding it.
///
/// A leak gives the plaintext to the caller, so there is a moment when it is
/// legitimately in hand and no photograph has to be taken from inside
/// anything. What it vouches for is the container the leak built, which is
/// where the absence below says nothing is left.
#[test]
fn test_what_a_leaked_vec_handed_back_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (secrets_box, mut watch, _) = filled()?;

    forensics!({
        let taken = capture(|| secrets_box.leak_a_vec())?;

        core::mem::forget(taken);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a leaked vec, and kept");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

/// A vec, whose bytes live in a heap block it reallocates.
///
/// The last round is written out rather than being the last turn of the loop,
/// because what it is handed has to still be alive when the capture runs: the
/// stack is then read as the leak left it and not as the drop left it. The drop
/// is after, and the photograph reads the allocation live.
#[test]
fn test_leak_a_vec_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        for _ in 0..ROUNDS - 1 {
            let taken = secrets_box.leak_a_vec()?;

            core::hint::black_box(taken.as_slice()[0]);
        }

        let taken = capture(|| secrets_box.leak_a_vec())?;

        drop(taken);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "leaked a vec",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::leak_an_array
// ============================================================================

/// What a leaked array handed back is found while it is held.
#[test]
fn test_what_a_leaked_array_handed_back_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (secrets_box, mut watch, _) = filled()?;

    forensics!({
        let taken = capture(|| secrets_box.leak_an_array())?;

        core::mem::forget(taken);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a leaked array, and kept");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

/// An array, whose bytes live in a box that never moves.
#[test]
fn test_leak_an_array_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        for _ in 0..ROUNDS - 1 {
            let taken = secrets_box.leak_an_array()?;

            core::hint::black_box(taken.as_slice()[0]);
        }

        let taken = capture(|| secrets_box.leak_an_array())?;

        drop(taken);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "leaked an array",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::leak_an_option
// ============================================================================

/// What a leaked option handed back is found while it is held.
#[test]
fn test_what_a_leaked_option_handed_back_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (secrets_box, mut watch, _) = filled()?;

    forensics!({
        let taken = capture(|| secrets_box.leak_an_option())?;

        core::mem::forget(taken);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a leaked option, and kept");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

/// An option around a vec, which has to take the value out and put it back.
#[test]
fn test_leak_an_option_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        for _ in 0..ROUNDS - 1 {
            let taken = secrets_box.leak_an_option()?;

            core::hint::black_box(taken.as_ref().is_some());
        }

        let taken = capture(|| secrets_box.leak_an_option())?;

        drop(taken);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "leaked an option",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::leak_two_options
// ============================================================================

/// What two leaked options handed back is found while it is held.
#[test]
fn test_what_two_leaked_options_handed_back_is_found_while_it_is_held() -> Result<(), AnyError> {
    let (secrets_box, mut watch, _) = filled()?;

    forensics!({
        let taken = capture(|| secrets_box.leak_two_options())?;

        core::mem::forget(taken);
    });

    let report = watch.snapshot()?;

    is_found(&report, "two leaked options, and kept");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

/// An option around an option, which takes the value out and puts it back
/// twice over.
#[test]
fn test_leak_two_options_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        for _ in 0..ROUNDS - 1 {
            let taken = secrets_box.leak_two_options()?;

            core::hint::black_box(taken.as_ref().is_some());
        }

        let taken = capture(|| secrets_box.leak_two_options())?;

        drop(taken);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "leaked two options",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::open_a_vec
// ============================================================================

#[test]
fn test_the_secret_is_found_while_a_vec_is_open() -> Result<(), AnyError> {
    let (secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open_a_vec(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while a vec is open");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_a_vec_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open_a_vec(|it| {
                    core::hint::black_box(it.len());

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened a vec",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_a_vec_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed = secrets_box.open_a_vec(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened a vec, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::open_an_array
// ============================================================================

#[test]
fn test_the_secret_is_found_while_an_array_is_open() -> Result<(), AnyError> {
    let (secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open_an_array(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while an array is open");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_an_array_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open_an_array(|it| {
                    core::hint::black_box(it.len());

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened an array",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_an_array_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed = secrets_box.open_an_array(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened an array, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::open_an_option
// ============================================================================

#[test]
fn test_the_secret_is_found_while_an_option_is_open() -> Result<(), AnyError> {
    let (secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open_an_option(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while an option is open");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_an_option_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open_an_option(|it| {
                    core::hint::black_box(it.as_ref().is_some());

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened an option",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_an_option_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed = secrets_box.open_an_option(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened an option, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::open_two_options
// ============================================================================

/// A field on its own decrypts through its own buffer and not through the one
/// the whole struct uses, so this is a different place for the plaintext to be
/// and needs saying separately.
#[test]
fn test_the_secret_is_found_while_one_field_is_open() -> Result<(), AnyError> {
    let (secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open_two_options(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while one field is open");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

/// One field, through the option that has to take its value out and put it back
/// twice over.
#[test]
fn test_open_field_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open_two_options(|it| {
                    core::hint::black_box(it.as_ref().is_some());

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened one field",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_two_options_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed =
                    secrets_box.open_two_options(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened two options, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::open_a_vec_mut
// ============================================================================

#[test]
fn test_the_secret_is_found_while_a_vec_is_open_for_writing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open_a_vec_mut(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while a vec is open for writing");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_a_vec_mut_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open_a_vec_mut(|it| {
                    core::hint::black_box(it.len());

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened a vec for writing",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_a_vec_mut_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed = secrets_box.open_a_vec_mut(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened a vec for writing, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::open_an_array_mut
// ============================================================================

#[test]
fn test_the_secret_is_found_while_an_array_is_open_for_writing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open_an_array_mut(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while an array is open for writing");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_an_array_mut_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open_an_array_mut(|it| {
                    core::hint::black_box(it.len());

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened an array for writing",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_an_array_mut_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed =
                    secrets_box.open_an_array_mut(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened an array for writing, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::open_an_option_mut
// ============================================================================

#[test]
fn test_the_secret_is_found_while_an_option_is_open_for_writing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open_an_option_mut(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while an option is open for writing");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_an_option_mut_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open_an_option_mut(|it| {
                    core::hint::black_box(it.as_ref().is_some());

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened an option for writing",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_an_option_mut_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed =
                    secrets_box.open_an_option_mut(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened an option for writing, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

// ============================================================================
// SecretsBox::open_two_options_mut
// ============================================================================

#[test]
fn test_the_secret_is_found_while_one_field_is_open_for_writing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, _) = filled()?;

    let mut inside = None;

    secrets_box.open_two_options_mut(|_| {
        inside = watch.snapshot().ok();

        Ok(())
    })?;

    let report = inside.ok_or(Reason::NoAnswer)?;

    is_found(&report, "the secret, while one field is open for writing");

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_field_mut_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                secrets_box.open_two_options_mut(|it| {
                    core::hint::black_box(it.as_ref().is_some());

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened one field for writing",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}

#[test]
fn test_open_two_options_mut_that_fails_leaves_nothing() -> Result<(), AnyError> {
    let (mut secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                let failed =
                    secrets_box.open_two_options_mut(|_| Err::<(), _>(CipherBoxError::Zeroized));

                core::hint::black_box(failed.is_err());
            }
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "filled, nothing opened",
        &report_after,
        "opened two options for writing, and failed",
    );

    drop(core::hint::black_box(secrets_box));

    Ok(())
}
