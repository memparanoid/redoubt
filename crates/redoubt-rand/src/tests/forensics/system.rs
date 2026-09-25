// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, capture, forensics, pick_spiller};

use crate::system::SystemEntropySource;
use crate::traits::EntropySource;

use crate::tests::forensics::support::{WIDE, backwards, is_found, leaves_nothing, wipe};

// ============================================================================
// SystemEntropySource::fill_bytes
// ============================================================================

#[test]
fn test_what_the_source_produced_is_found_while_the_buffer_holds_it() -> Result<(), AnyError> {
    // CORRECTNESS: before the block. The capture runs the form this picks, and
    // the watch that would otherwise pick it is built after the capture.
    pick_spiller();

    let source = SystemEntropySource {};
    let mut got = vec![0_u8; WIDE];

    forensics!({
        let asked = capture(|| source.fill_bytes(&mut got));

        asked?;
    });

    let mut watch = Forensics::watching(&backwards(&got))?;

    let report = watch.snapshot()?;

    is_found(
        &report,
        "the bytes the source produced, still in the buffer",
    );

    wipe(&mut got);

    Ok(())
}

#[test]
fn test_asking_the_source_leaves_nothing() -> Result<(), AnyError> {
    // CORRECTNESS: before the block. The capture runs the form this picks, and
    // the watch that would otherwise pick it is built after the capture.
    pick_spiller();

    let source = SystemEntropySource {};
    let mut got = vec![0_u8; WIDE];

    forensics!({
        let asked = capture(|| source.fill_bytes(&mut got));

        asked?;
    });

    // CORRECTNESS: after the capture. A call made before it writes over the
    // stack and the registers the operation left, and then the absence below is
    // about that call and not about the operation.
    let needle = backwards(&got);

    wipe(&mut got);

    let mut watch = Forensics::watching(&needle)?;

    let report = watch.snapshot()?;

    leaves_nothing(
        &report,
        "the bytes the source produced, and the buffer wiped",
    );

    Ok(())
}
