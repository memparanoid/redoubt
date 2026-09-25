// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_mem_core::copy_nonoverlapping;

use crate::support::needles::{BIG, SECRET, backwards};
use crate::support::{is_found, leaves_nothing, wipe};

/// Copies in a row: a residue that survives one copy in fifty shows here and
/// not in a single one.
const ROUNDS: usize = 200;

// ============================================================================
// copy_nonoverlapping
// ============================================================================

#[test]
fn test_a_copy_is_found_in_its_destination() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut scratch = vec![0_u8; SECRET.len()];

    forensics!({
        capture(|| {
            // SAFETY: `scratch` is exactly the secret's length, and a constant
            // and a heap block are different allocations.
            unsafe { copy_nonoverlapping(SECRET.as_ptr(), scratch.as_mut_ptr(), SECRET.len()) };
        });
    });

    let report = watch.snapshot()?;

    is_found(&report, "a copy, left in its destination");

    wipe(&mut scratch);

    drop(core::hint::black_box(scratch));

    Ok(())
}

#[test]
fn test_copying_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut scratch = vec![0_u8; SECRET.len()];

    forensics!({
        capture(|| {
            // SAFETY: `scratch` is exactly the secret's length, and a constant
            // and a heap block are different allocations.
            unsafe { copy_nonoverlapping(SECRET.as_ptr(), scratch.as_mut_ptr(), SECRET.len()) };
        });

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut scratch);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, "nothing held yet", &report_after, "a copy");

    drop(core::hint::black_box(scratch));

    Ok(())
}

#[test]
fn test_two_hundred_copies_leave_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut scratch = vec![0_u8; SECRET.len()];

    forensics!({
        capture(|| {
            for _ in 0..ROUNDS {
                // SAFETY: `scratch` is exactly the secret's length, and a
                // constant and a heap block are different allocations.
                unsafe { copy_nonoverlapping(SECRET.as_ptr(), scratch.as_mut_ptr(), SECRET.len()) };
            }
        });

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut scratch);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &report_after,
        &format!("{ROUNDS} copies"),
    );

    drop(core::hint::black_box(scratch));

    Ok(())
}

macro_rules! copied {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut scratch = vec![0_u8; $of];

            forensics!({
                capture(|| {
                    // SAFETY: `scratch` is `$of` long, `$of` never passes
                    // `BIG`'s length, and a constant and a heap block are
                    // different allocations.
                    unsafe { copy_nonoverlapping(BIG.as_ptr(), scratch.as_mut_ptr(), $of) };
                });

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                wipe(&mut scratch);
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                "nothing held yet",
                &report_after,
                &format!("a copy of {} bytes", $of),
            );

            drop(core::hint::black_box(scratch));

            Ok(())
        }
    };
}

copied!(test_copying_32_bytes_leaves_nothing, 32);
copied!(test_copying_33_bytes_leaves_nothing, 33);
copied!(test_copying_63_bytes_leaves_nothing, 63);
copied!(test_copying_64_bytes_leaves_nothing, 64);
copied!(test_copying_65_bytes_leaves_nothing, 65);
copied!(test_copying_127_bytes_leaves_nothing, 127);
copied!(test_copying_128_bytes_leaves_nothing, 128);
copied!(test_copying_129_bytes_leaves_nothing, 129);
copied!(test_copying_511_bytes_leaves_nothing, 511);
copied!(test_copying_512_bytes_leaves_nothing, 512);
copied!(test_copying_513_bytes_leaves_nothing, 513);
copied!(test_copying_1024_bytes_leaves_nothing, 1024);
copied!(test_copying_4096_bytes_leaves_nothing, 4096);
copied!(test_copying_8192_bytes_leaves_nothing, 8192);
