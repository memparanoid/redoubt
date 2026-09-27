// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What opening the master key, and deriving a box's key from it, leaves
//! behind.

mod buffer;
mod storage;

use redoubt_buffer::BufferError;
use redoubt_forensics::{AnyError, Forensics, QUIET, capture, forensics};

use crate::master_key::consts::{CIPHERBOX_KEY_INFO_LEN, MASTER_KEY_LEN};
use crate::master_key::storage::open;
use crate::master_key::{cipherbox_key_info, derive_cipherbox_key, leak_master_key};

use super::support::needles::backwards_through;
use super::support::{is_found, leaves_nothing};

/// Rounds in a row: a piece that survives one round in fifty shows here and
/// not once.
const ROUNDS: usize = 200;

fn info() -> [u8; CIPHERBOX_KEY_INFO_LEN] {
    cipherbox_key_info(1, 2)
}

fn derived_key_backwards() -> Result<Vec<u8>, AnyError> {
    let mut needle = derive_cipherbox_key(MASTER_KEY_LEN, &info())?;

    needle.reverse();

    Ok(needle.to_vec())
}

// ============================================================================
// cipherbox_key_info
// ============================================================================

#[test]
#[ignore = "Reads no secret: the prefix, the pid and the uid are public."]
fn test_making_the_key_info_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// derive_cipherbox_key
// ============================================================================

#[redoubt_forensics::test]
fn test_the_derived_key_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&derived_key_backwards()?)?;
    let info = info();

    forensics!({
        let held = capture(|| derive_cipherbox_key(MASTER_KEY_LEN, &info))?;

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "the derived key, held");

    Ok(())
}

#[redoubt_forensics::test]
fn test_deriving_a_key_once_leaves_nothing() -> Result<(), AnyError> {
    let mut master = Forensics::watching(&backwards_through(open)?)?;
    let mut derived = Forensics::watching(&derived_key_backwards()?)?;

    let master_before = master.snapshot()?;
    let derived_before = derived.snapshot()?;

    let info = info();

    forensics!({
        let key = capture(|| derive_cipherbox_key(MASTER_KEY_LEN, &info))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(key);
    });

    let master_after = master.snapshot()?;
    let derived_after = derived.snapshot()?;

    leaves_nothing(
        &master_before,
        "nothing held yet",
        &master_after,
        "one derive, in the master key",
    );
    leaves_nothing(
        &derived_before,
        "nothing held yet",
        &derived_after,
        "one derive, in the derived key",
    );

    Ok(())
}

#[redoubt_forensics::test]
fn test_deriving_a_key_often_leaves_nothing() -> Result<(), AnyError> {
    let mut master = Forensics::watching(&backwards_through(open)?)?;
    let mut derived = Forensics::watching(&derived_key_backwards()?)?;

    let master_before = master.snapshot()?;
    let derived_before = derived.snapshot()?;

    let info = info();

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                let key = derive_cipherbox_key(MASTER_KEY_LEN, &info)?;

                core::hint::black_box(key[0]);
            }

            Ok(())
        })?;
    });

    let master_after = master.snapshot()?;
    let derived_after = derived.snapshot()?;

    leaves_nothing(
        &master_before,
        "nothing held yet",
        &master_after,
        &format!("{ROUNDS} derives, in the master key"),
    );
    leaves_nothing(
        &derived_before,
        "nothing held yet",
        &derived_after,
        &format!("{ROUNDS} derives, in the derived key"),
    );

    Ok(())
}

#[redoubt_forensics::test]
fn test_deriving_a_key_too_wide_leaves_nothing() -> Result<(), AnyError> {
    let mut master = Forensics::watching(&backwards_through(open)?)?;
    let mut derived = Forensics::watching(&derived_key_backwards()?)?;

    let master_before = master.snapshot()?;
    let derived_before = derived.snapshot()?;

    let info = info();

    forensics!({
        let refused = capture(|| derive_cipherbox_key(MASTER_KEY_LEN + 1, &info));

        assert!(
            matches!(refused, Err(BufferError::CallbackError(_))),
            "a width past the key was not refused"
        );
    });

    let master_after = master.snapshot()?;
    let derived_after = derived.snapshot()?;

    leaves_nothing(
        &master_before,
        "nothing held yet",
        &master_after,
        "a derive too wide, in the master key",
    );
    leaves_nothing(
        &derived_before,
        "nothing held yet",
        &derived_after,
        "a derive too wide, in the derived key",
    );

    Ok(())
}

// ============================================================================
// leak_master_key
// ============================================================================

#[redoubt_forensics::test]
fn test_the_master_key_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards_through(open)?)?;

    forensics!({
        let held = capture(|| leak_master_key(MASTER_KEY_LEN))?;

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "the key, held");

    Ok(())
}

#[redoubt_forensics::test]
fn test_a_piece_of_the_master_key_kept_is_not_read_as_chance() -> Result<(), AnyError> {
    /// As wide as the widest run [`QUIET`] allows.
    const PIECE: usize = QUIET as usize;

    let mut watch = Forensics::watching(&backwards_through(open)?)?;

    let report_before = watch.snapshot()?;

    let kept = {
        let key = leak_master_key(MASTER_KEY_LEN)?;

        key[8..8 + PIECE].to_vec()
    };

    core::hint::black_box(&kept);

    let report_after = watch.snapshot()?;
    let delta = report_after.against(&report_before);

    println!();
    report_before.summary("nothing kept yet");
    report_after.summary_against(&report_before, &format!("{PIECE} bytes kept"));
    println!();

    assert!(
        !report_after.found,
        "a search for the whole key found {PIECE} bytes of it, which it cannot: \
         {report_after}",
    );

    assert!(
        report_after.widest >= PIECE as u64,
        "{PIECE} bytes of the key are in plain sight and the widest run is {}: \
         {report_after}",
        report_after.widest,
    );

    assert!(
        !delta.is_noise(),
        "{PIECE} bytes of the key read as chance, which is what {QUIET} says \
         they are not: {delta}",
    );

    drop(core::hint::black_box(kept));

    Ok(())
}

#[redoubt_forensics::test]
fn test_opening_the_master_key_too_wide_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards_through(open)?)?;

    let report_before = watch.snapshot()?;

    forensics!({
        let refused = capture(|| leak_master_key(MASTER_KEY_LEN + 1));

        assert!(
            matches!(refused, Err(BufferError::CallbackError(_))),
            "a width past the key was not refused"
        );
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &report_after,
        "an open too wide",
    );

    Ok(())
}

#[redoubt_forensics::test]
fn test_opening_the_master_key_once_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards_through(open)?)?;

    let report_before = watch.snapshot()?;

    forensics!({
        let key = capture(|| leak_master_key(MASTER_KEY_LEN))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        drop(key);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &report_after,
        "one open",
    );

    Ok(())
}

#[redoubt_forensics::test]
fn test_opening_the_master_key_often_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards_through(open)?)?;

    let report_before = watch.snapshot()?;

    forensics!({
        capture(|| -> Result<(), AnyError> {
            for _ in 0..ROUNDS {
                let key = leak_master_key(MASTER_KEY_LEN)?;

                core::hint::black_box(key[0]);
            }

            Ok(())
        })?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &report_after,
        &format!("{ROUNDS} opens"),
    );

    Ok(())
}
