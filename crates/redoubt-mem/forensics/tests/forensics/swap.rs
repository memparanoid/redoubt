// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, capture, forensics, is_found, leaves_nothing};
use redoubt_mem_core::{copy_nonoverlapping, swap, swap_nonoverlapping};

use crate::support::needles::{BIG, SECRET, backwards};
use crate::support::wipe;

/// Thirty-two bytes of the secret in a box, through the copy being measured
/// elsewhere in this crate.
fn hold() -> Box<[u8; 32]> {
    let mut held = Box::new([0_u8; 32]);

    // SAFETY: a constant and a heap block are different allocations, and both
    // are thirty-two bytes.
    unsafe { copy_nonoverlapping(SECRET.as_ptr(), held.as_mut_ptr(), 32) };

    held
}

// ============================================================================
// swap
// ============================================================================

#[redoubt_forensics::test]
fn test_a_swap_is_found_where_it_moved_the_secret() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let secret = Box::leak(hold());
        let empty = Box::leak(Box::new([0_u8; 32]));

        capture(|| swap(secret, empty));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a swap, left where it moved it");

    Ok(())
}

#[redoubt_forensics::test]
fn test_swapping_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut secret = hold();
    let mut empty = Box::new([0_u8; 32]);

    forensics!({
        capture(|| swap(&mut *secret, &mut *empty));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // Only the side the secret was swapped into is emptied: the side it
        // left is the swap's to leave empty, and emptying it here would keep
        // this green for a swap that only copied.
        wipe(&mut *empty);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a swap");

    Ok(())
}

// ============================================================================
// swap_nonoverlapping
// ============================================================================

#[redoubt_forensics::test]
fn test_a_sized_swap_is_found_where_it_moved_the_secret() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut secret = vec![0_u8; SECRET.len()];

    // SAFETY: a constant and a heap block are different allocations.
    unsafe { copy_nonoverlapping(SECRET.as_ptr(), secret.as_mut_ptr(), SECRET.len()) };

    forensics!({
        // Leaked and not a local: a local is dropped at the end of the block,
        // and its drop empties or frees what the operation wrote before the
        // photograph.
        let empty = vec![0_u8; SECRET.len()].leak();

        capture(|| {
            // SAFETY: two different allocations, both the secret's length.
            unsafe { swap_nonoverlapping(secret.as_mut_ptr(), empty.as_mut_ptr(), SECRET.len()) };
        });
    });

    let report = watch.snapshot()?;

    is_found(&report, "a sized swap, left where it moved it");

    Ok(())
}

macro_rules! swapped {
    ($name:ident, $of:expr) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut secret = vec![0_u8; $of];
            let mut empty = vec![0_u8; $of];

            // SAFETY: `secret` is `$of` long, `$of` never passes `BIG`'s
            // length, and a constant and a heap block are different
            // allocations.
            unsafe { copy_nonoverlapping(BIG.as_ptr(), secret.as_mut_ptr(), $of) };

            forensics!({
                capture(|| {
                    // SAFETY: two different allocations, both `$of` long.
                    unsafe { swap_nonoverlapping(secret.as_mut_ptr(), empty.as_mut_ptr(), $of) };
                });

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                //
                // Only the side the secret was swapped into is emptied: the
                // side it left is the swap's to leave empty, and emptying it
                // here would keep this green for a swap that only copied.
                wipe(&mut empty);
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a swap of {} bytes", $of),
            );

            Ok(())
        }
    };
}

swapped!(test_swapping_32_bytes_leaves_nothing, 32);
swapped!(test_swapping_33_bytes_leaves_nothing, 33);
swapped!(test_swapping_63_bytes_leaves_nothing, 63);
swapped!(test_swapping_64_bytes_leaves_nothing, 64);
swapped!(test_swapping_65_bytes_leaves_nothing, 65);
swapped!(test_swapping_127_bytes_leaves_nothing, 127);
swapped!(test_swapping_128_bytes_leaves_nothing, 128);
swapped!(test_swapping_129_bytes_leaves_nothing, 129);
swapped!(test_swapping_511_bytes_leaves_nothing, 511);
swapped!(test_swapping_512_bytes_leaves_nothing, 512);
swapped!(test_swapping_513_bytes_leaves_nothing, 513);
swapped!(test_swapping_1024_bytes_leaves_nothing, 1024);
swapped!(test_swapping_4096_bytes_leaves_nothing, 4096);
swapped!(test_swapping_8192_bytes_leaves_nothing, 8192);
