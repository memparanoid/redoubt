// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::AllockedVec;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::support::needles::{SECRET, backwards};
use crate::support::{Block, blocks, giving, hold_on, is_found, leaves_nothing, let_go};

// ============================================================================
// AllockedVec::drop
// ============================================================================

/// One size dropped.
macro_rules! an_allocked_vec_dropped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                for one in &mut source {
                    held.push(one)?;
                }

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| drop(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an allocked vec of {} bytes dropped", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_dropped!(test_an_allocked_vec_of_32_dropped_leaves_nothing, 32);
an_allocked_vec_dropped!(test_an_allocked_vec_of_64_dropped_leaves_nothing, 64);
an_allocked_vec_dropped!(test_an_allocked_vec_of_128_dropped_leaves_nothing, 128);
an_allocked_vec_dropped!(test_an_allocked_vec_of_512_dropped_leaves_nothing, 512);
an_allocked_vec_dropped!(test_an_allocked_vec_of_1024_dropped_leaves_nothing, 1024);
an_allocked_vec_dropped!(test_an_allocked_vec_of_4096_dropped_leaves_nothing, 4096);
an_allocked_vec_dropped!(test_an_allocked_vec_of_16384_dropped_leaves_nothing, 16384);
an_allocked_vec_dropped!(test_an_allocked_vec_of_65536_dropped_leaves_nothing, 65536);

// ============================================================================
// AllockedVec: ownership
// ============================================================================

/// A vec given away is found while whoever took it is holding it.
#[test]
fn test_an_allocked_vec_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        held.push(&mut { SECRET })?;

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "an allocked vec given away, and kept");

    Ok(())
}

/// One size given away.
macro_rules! an_allocked_vec_given_away {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                for one in &mut source {
                    held.push(one)?;
                }

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| let_go(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an allocked vec of {} bytes given away", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_given_away!(test_an_allocked_vec_of_32_given_away_leaves_nothing, 32);
an_allocked_vec_given_away!(test_an_allocked_vec_of_64_given_away_leaves_nothing, 64);
an_allocked_vec_given_away!(test_an_allocked_vec_of_128_given_away_leaves_nothing, 128);
an_allocked_vec_given_away!(test_an_allocked_vec_of_512_given_away_leaves_nothing, 512);
an_allocked_vec_given_away!(test_an_allocked_vec_of_1024_given_away_leaves_nothing, 1024);
an_allocked_vec_given_away!(test_an_allocked_vec_of_4096_given_away_leaves_nothing, 4096);
an_allocked_vec_given_away!(
    test_an_allocked_vec_of_16384_given_away_leaves_nothing,
    16384
);
an_allocked_vec_given_away!(
    test_an_allocked_vec_of_65536_given_away_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec: Debug
// ============================================================================

#[test]
#[ignore = "Reads no secret: it prints the length and the capacity, and \
            redacts the contents."]
fn test_formatting_an_allocked_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::realloc_with
// ============================================================================

#[test]
#[ignore = "Covered transitively: `realloc_with_capacity` is what reaches it \
            outside the crate, and its section measures it."]
fn test_an_allocked_vec_reallocated_with_a_hook_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty container."]
fn test_making_an_allocked_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::with_capacity
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty container."]
fn test_making_an_allocked_vec_with_capacity_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::reserve_exact
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes zeros over capacity nothing has filled."]
fn test_an_allocked_vec_reserved_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::push
// ============================================================================

/// What is pushed is found while the vec holds it.
///
/// The value comes out of the constant, which lives where nothing may write,
/// so the only writable copy in the process is the one `push` made.
#[test]
fn test_what_was_pushed_is_found_while_the_allocked_vec_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        capture(|| held.push(&mut { SECRET }))?;

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec pushed into, and kept");

    Ok(())
}

/// One size pushed in a block at a time, and let go.
///
/// A value taken by `push` is a value copied out of the caller's slot, and the
/// vec never reallocates here, so what is left is whatever those copies left.
macro_rules! an_allocked_vec_pushed_into {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                capture(|| -> Result<(), AnyError> {
                    for one in &mut source {
                        held.push(one)?;
                    }

                    Ok(())
                })?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes pushed into", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_pushed_into!(test_an_allocked_vec_of_32_pushed_into_leaves_nothing, 32);
an_allocked_vec_pushed_into!(test_an_allocked_vec_of_64_pushed_into_leaves_nothing, 64);
an_allocked_vec_pushed_into!(test_an_allocked_vec_of_128_pushed_into_leaves_nothing, 128);
an_allocked_vec_pushed_into!(test_an_allocked_vec_of_512_pushed_into_leaves_nothing, 512);
an_allocked_vec_pushed_into!(
    test_an_allocked_vec_of_1024_pushed_into_leaves_nothing,
    1024
);
an_allocked_vec_pushed_into!(
    test_an_allocked_vec_of_4096_pushed_into_leaves_nothing,
    4096
);
an_allocked_vec_pushed_into!(
    test_an_allocked_vec_of_16384_pushed_into_leaves_nothing,
    16384
);
an_allocked_vec_pushed_into!(
    test_an_allocked_vec_of_65536_pushed_into_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec::len
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_the_length_of_an_allocked_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::capacity
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_the_capacity_of_an_allocked_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::is_empty
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_whether_an_allocked_vec_is_empty_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::as_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_an_allocked_vec_as_a_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::as_mut_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_an_allocked_vec_as_a_mut_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::truncate
// ============================================================================

/// The tail is found while it is still the vec's.
///
/// What the absence below is measured against: the sweep reaches the storage a
/// truncation is about to cut, so a clean answer afterwards is the cut and not
/// the instrument. Before and not after, because the type hands back nothing it
/// removed — there is no `pop` — so a cut tail exists nowhere to be found.
#[test]
fn test_what_a_truncation_will_cut_is_found_before_it_is_cut() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        capture(|| held.push(&mut { SECRET }))?;

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec filled, before anything was cut");

    Ok(())
}

/// One size filled and cut back to nothing.
macro_rules! an_allocked_vec_truncated {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                for one in &mut source {
                    held.push(one)?;
                }

                capture(|| held.truncate(0));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes truncated", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_truncated!(test_an_allocked_vec_of_32_truncated_leaves_nothing, 32);
an_allocked_vec_truncated!(test_an_allocked_vec_of_64_truncated_leaves_nothing, 64);
an_allocked_vec_truncated!(test_an_allocked_vec_of_128_truncated_leaves_nothing, 128);
an_allocked_vec_truncated!(test_an_allocked_vec_of_512_truncated_leaves_nothing, 512);
an_allocked_vec_truncated!(test_an_allocked_vec_of_1024_truncated_leaves_nothing, 1024);
an_allocked_vec_truncated!(test_an_allocked_vec_of_4096_truncated_leaves_nothing, 4096);
an_allocked_vec_truncated!(
    test_an_allocked_vec_of_16384_truncated_leaves_nothing,
    16384
);
an_allocked_vec_truncated!(
    test_an_allocked_vec_of_65536_truncated_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec::drain_from
// ============================================================================

/// What was drained is found while the vec holds it.
#[test]
fn test_what_was_drained_is_found_while_the_allocked_vec_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![[0_u8; SECRET.len()]];

    giving(&mut source[0]);

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        capture(|| held.drain_from(&mut source))?;

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec drained into, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// One size drained out of a slice the caller owns.
///
/// The source is the caller's and the operation is what empties it, so this
/// section asks about two places at once: what the call left of its own, and
/// what it left in the slice it was handed.
macro_rules! an_allocked_vec_drained_into {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));
                capture(|| held.drain_from(&mut source))?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes drained into", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_drained_into!(test_an_allocked_vec_of_32_drained_into_leaves_nothing, 32);
an_allocked_vec_drained_into!(test_an_allocked_vec_of_64_drained_into_leaves_nothing, 64);
an_allocked_vec_drained_into!(test_an_allocked_vec_of_128_drained_into_leaves_nothing, 128);
an_allocked_vec_drained_into!(test_an_allocked_vec_of_512_drained_into_leaves_nothing, 512);
an_allocked_vec_drained_into!(
    test_an_allocked_vec_of_1024_drained_into_leaves_nothing,
    1024
);
an_allocked_vec_drained_into!(
    test_an_allocked_vec_of_4096_drained_into_leaves_nothing,
    4096
);
an_allocked_vec_drained_into!(
    test_an_allocked_vec_of_16384_drained_into_leaves_nothing,
    16384
);
an_allocked_vec_drained_into!(
    test_an_allocked_vec_of_65536_drained_into_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec::realloc_with_capacity
// ============================================================================

/// What was carried over is found while the vec holds it.
///
/// The photograph is taken with the new allocation still held, which is where
/// the reallocation put the bytes it copied.
#[test]
fn test_what_was_carried_over_is_found_while_the_allocked_vec_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut held = AllockedVec::<Block>::with_capacity(1);
        held.push(&mut { SECRET })?;

        capture(|| held.realloc_with_capacity(2));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec reallocated, and kept");

    Ok(())
}

/// One size carried into a wider allocation, and let go.
///
/// The only operation here that moves a secret from one allocation to another.
/// What the absence asks about is the block it outgrew, which the call empties
/// after it has copied out of it.
macro_rules! an_allocked_vec_reallocated {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let mut source = vec![[0_u8; SECRET.len()]; blocks($of)];

            for one in &mut source {
                giving(one);
            }

            let report_before = watch.snapshot()?;

            forensics!({
                let mut held = AllockedVec::<Block>::with_capacity(blocks($of));

                for one in &mut source {
                    held.push(one)?;
                }

                capture(|| held.realloc_with_capacity(blocks($of) * 2));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec of {} bytes reallocated", $of),
            );

            Ok(())
        }
    };
}

an_allocked_vec_reallocated!(test_an_allocked_vec_of_32_reallocated_leaves_nothing, 32);
an_allocked_vec_reallocated!(test_an_allocked_vec_of_64_reallocated_leaves_nothing, 64);
an_allocked_vec_reallocated!(test_an_allocked_vec_of_128_reallocated_leaves_nothing, 128);
an_allocked_vec_reallocated!(test_an_allocked_vec_of_512_reallocated_leaves_nothing, 512);
an_allocked_vec_reallocated!(
    test_an_allocked_vec_of_1024_reallocated_leaves_nothing,
    1024
);
an_allocked_vec_reallocated!(
    test_an_allocked_vec_of_4096_reallocated_leaves_nothing,
    4096
);
an_allocked_vec_reallocated!(
    test_an_allocked_vec_of_16384_reallocated_leaves_nothing,
    16384
);
an_allocked_vec_reallocated!(
    test_an_allocked_vec_of_65536_reallocated_leaves_nothing,
    65536
);

// ============================================================================
// AllockedVec::fill_with_default
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes defaults."]
fn test_an_allocked_vec_filled_with_defaults_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::as_mut_ptr
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a pointer."]
fn test_an_allocked_vec_as_a_mut_ptr_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::as_capacity_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_an_allocked_vec_as_a_capacity_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::as_capacity_mut_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_an_allocked_vec_as_a_capacity_mut_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec::set_len
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes a length."]
fn test_setting_the_length_of_an_allocked_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec: Default
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty container."]
fn test_a_default_allocked_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AllockedVec: Deref
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_dereferencing_an_allocked_vec_leaves_nothing() {
    // Intentionally empty.
}
