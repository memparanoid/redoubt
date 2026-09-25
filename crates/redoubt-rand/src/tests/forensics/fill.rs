// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, capture, forensics, pick_spiller};

use crate::error::EntropyError;
use crate::fill::fill_with_random_bytes;

use crate::tests::forensics::support::{
    WIDE, backwards, is_found, leaves_nothing, leaves_nothing_since, wipe,
};

/// More than one piece the routine is asked for, and a last piece that is not
/// whole: the wrapper's loop and its tail.
const WIDER: usize = 4 * 256 + 32;

/// A path that keeps a piece of an older request shows only over many.
const ROUNDS: usize = 200;

fn asking_leaves_nothing(len: usize) -> Result<(), AnyError> {
    // CORRECTNESS: before the block. The capture runs the form this picks, and
    // the watch that would otherwise pick it is built after the capture.
    pick_spiller();

    let mut got = vec![0_u8; len];

    forensics!({
        let asked = capture(|| fill_with_random_bytes(&mut got));

        asked?;
    });

    // CORRECTNESS: after the capture. A call made before it writes over the
    // stack and the registers the operation left, and then the absence below is
    // about that call and not about the operation.
    let needle = backwards(&got);

    wipe(&mut got);

    let mut watch = Forensics::watching(&needle)?;

    let report = watch.snapshot()?;

    leaves_nothing(&report, "the bytes asked for, and the buffer wiped");

    Ok(())
}

// ============================================================================
// fill_with_random_bytes
// ============================================================================

#[test]
fn test_what_was_asked_for_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    // CORRECTNESS: before the block. The capture runs the form this picks, and
    // the watch that would otherwise pick it is built after the capture.
    pick_spiller();

    let mut got = vec![0_u8; WIDE];

    forensics!({
        let asked = capture(|| fill_with_random_bytes(&mut got));

        asked?;
    });

    let mut watch = Forensics::watching(&backwards(&got))?;

    let report = watch.snapshot()?;

    is_found(&report, "the bytes asked for, still in the buffer");

    wipe(&mut got);

    Ok(())
}

#[test]
fn test_asking_for_bytes_leaves_nothing() -> Result<(), AnyError> {
    asking_leaves_nothing(WIDE)
}

#[test]
fn test_asking_for_more_than_one_piece_leaves_nothing() -> Result<(), AnyError> {
    asking_leaves_nothing(WIDER)
}

/// Each round asks for bytes of its own and wipes them; the needle is the first
/// request's, which exists before the photograph that opens the test.
#[test]
fn test_two_hundred_requests_leave_nothing_of_the_first() -> Result<(), AnyError> {
    let mut got = vec![0_u8; WIDE];

    fill_with_random_bytes(&mut got)?;

    let needle = backwards(&got);

    wipe(&mut got);

    let mut watch = Forensics::watching(&needle)?;

    let report_before = watch.snapshot()?;

    forensics!({
        let asked = capture(|| -> Result<(), EntropyError> {
            for _ in 0..ROUNDS {
                let mut round = vec![0_u8; WIDE];

                fill_with_random_bytes(&mut round)?;

                wipe(&mut round);
            }

            Ok(())
        });

        asked?;
    });

    let report_after = watch.snapshot()?;

    leaves_nothing_since(&report_before, &report_after, "two hundred more requests");

    Ok(())
}
