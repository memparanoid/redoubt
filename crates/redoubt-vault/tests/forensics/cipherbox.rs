// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each way of opening a cipherbox leaves behind.

use redoubt_alloc::{RedoubtArray, RedoubtOption, RedoubtVec};
use redoubt_codec::RedoubtCodec;
use redoubt_forensics::{AnyError, Forensics, QUIET, Reason, Report, capture, forensics};
use redoubt_vault::{CipherBoxError, cipherbox};
use redoubt_zero::RedoubtZero;

use crate::support::needles::{SECRET, backwards};
use crate::support::{giving, is_found, leaves_nothing};

/// Rounds per absence, so a residue that survives only now and then still
/// accumulates where the sweep reads it.
const ROUNDS: usize = 200;

/// Copies of the secret in each vec field: thirty-two kilobytes, so every
/// buffer on the way into the ciphertext is that large too.
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

/// Fills every field inside one `open_mut`, from sources the containers empty.
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

        // Room asked for up front, so the replace below never reaches
        // `grow_to`: a payload this size with no growth tells a leak in the
        // growing apart from one in the carrying.
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

/// A filled box, the instrument watching, and the photograph after the fill.
/// The fill comes before it so a test reads what opening left, and it is held
/// to the bound because every test reads a difference from it.
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

/// Takes the value by move and drops it. Not inlined, so the move is not
/// folded away.
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
        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
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

/// No presence of its own: at rest the box holds ciphertext, so a moved box has
/// no plaintext to find. The absence leans on the presences of the opening
/// methods.
#[test]
fn test_a_box_given_away_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut secrets_box = SecretsBox::new();

    forensics!({
        open_fill_and_close(&mut secrets_box)?;

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
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

/// The box is alive and full when the photograph is taken. Its control is the
/// `open` presence: the same box, open, holds the whole secret.
#[test]
fn test_a_filled_box_holds_nothing_at_rest() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut secrets_box = SecretsBox::new();

    forensics!({
        capture(|| open_fill_and_close(&mut secrets_box))?;
    });

    // Held across the photograph, by reference: let go before it, the
    // photograph would read the drop and not what the box keeps.
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

/// Every field replaced inside one `open_mut`, which is the fill every other
/// test here starts from.
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

/// Only a residue that accumulates across fills, or a container that leaves its
/// old contents as it grows, fails here and not after a single fill.
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

#[test]
fn test_leak_a_vec_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        for _ in 0..ROUNDS - 1 {
            let taken = secrets_box.leak_a_vec()?;

            core::hint::black_box(taken.as_slice()[0]);
        }

        let taken = capture(|| secrets_box.leak_a_vec())?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
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

#[test]
fn test_leak_an_array_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        for _ in 0..ROUNDS - 1 {
            let taken = secrets_box.leak_an_array()?;

            core::hint::black_box(taken.as_slice()[0]);
        }

        let taken = capture(|| secrets_box.leak_an_array())?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
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

#[test]
fn test_leak_an_option_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        for _ in 0..ROUNDS - 1 {
            let taken = secrets_box.leak_an_option()?;

            core::hint::black_box(taken.as_ref().is_some());
        }

        let taken = capture(|| secrets_box.leak_an_option())?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
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

#[test]
fn test_leak_two_options_leaves_nothing() -> Result<(), AnyError> {
    let (secrets_box, mut watch, report_before) = filled()?;

    forensics!({
        for _ in 0..ROUNDS - 1 {
            let taken = secrets_box.leak_two_options()?;

            core::hint::black_box(taken.as_ref().is_some());
        }

        let taken = capture(|| secrets_box.leak_two_options())?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
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
