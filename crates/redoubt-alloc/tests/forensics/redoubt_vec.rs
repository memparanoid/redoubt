// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::RedoubtVec;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::support::needles::{SECRET, backwards};
use crate::support::{giving, hold_on, is_found, leaves_nothing, let_go};

// ============================================================================
// RedoubtVec::drop
// ============================================================================

/// A vec dropped at one size.
macro_rules! a_redoubt_vec_dropped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut held = RedoubtVec::<u8>::new();
                held.replace_from_mut_slice(&mut source);

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
                &format!("a vec of {} bytes dropped", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_vec_dropped!(test_a_redoubt_vec_of_32_dropped_leaves_nothing, 32);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_64_dropped_leaves_nothing, 64);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_128_dropped_leaves_nothing, 128);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_512_dropped_leaves_nothing, 512);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_1024_dropped_leaves_nothing, 1024);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_4096_dropped_leaves_nothing, 4096);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_8192_dropped_leaves_nothing, 8192);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_16384_dropped_leaves_nothing, 16384);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_32768_dropped_leaves_nothing, 32768);
a_redoubt_vec_dropped!(test_a_redoubt_vec_of_65536_dropped_leaves_nothing, 65536);

// ============================================================================
// RedoubtVec: ownership
// ============================================================================

/// A vec given away is found while whoever took it is holding it.
#[test]
fn test_a_redoubt_vec_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtVec::<u8>::new();
        held.replace_from_mut_slice(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec given away, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// A vec given away at one size.
///
/// The question an ownership section asks is not whether the drop empties the
/// value — the replaces ask that. It is whether *moving* it first changes the
/// answer, because a value that keeps its secret in its own bytes leaves the
/// slot it was moved out of with nobody to empty it.
///
/// What makes the answer no is one word in the declaration: the secret is
/// behind a `Box`, so what travels is the pointer and the bytes never move.
macro_rules! a_redoubt_vec_given_away {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut held = RedoubtVec::<u8>::new();
                held.replace_from_mut_slice(&mut source);

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
                &format!("a vec of {} bytes given away", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_vec_given_away!(test_a_redoubt_vec_of_32_given_away_leaves_nothing, 32);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_64_given_away_leaves_nothing, 64);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_128_given_away_leaves_nothing, 128);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_512_given_away_leaves_nothing, 512);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_1024_given_away_leaves_nothing, 1024);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_4096_given_away_leaves_nothing, 4096);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_8192_given_away_leaves_nothing, 8192);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_16384_given_away_leaves_nothing, 16384);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_32768_given_away_leaves_nothing, 32768);
a_redoubt_vec_given_away!(test_a_redoubt_vec_of_65536_given_away_leaves_nothing, 65536);

// ============================================================================
// RedoubtVec: Debug
// ============================================================================

#[test]
#[ignore = "Reads no secret: it prints the length and the capacity, and \
            redacts the contents."]
fn test_formatting_a_redoubt_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty container."]
fn test_making_a_redoubt_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::with_capacity
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty container."]
fn test_making_a_redoubt_vec_with_capacity_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::from_mut_slice
// ============================================================================

#[test]
#[ignore = "TODO: it takes the secret, and nothing measures it yet."]
fn test_a_redoubt_vec_from_a_mut_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::len
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_the_length_of_a_redoubt_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::is_empty
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_whether_a_redoubt_vec_is_empty_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::capacity
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_the_capacity_of_a_redoubt_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::grow_to
// ============================================================================

#[test]
#[ignore = "Covered transitively: private, and every section that grows the \
            vec past its capacity runs it."]
fn test_a_redoubt_vec_grown_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::maybe_grow_to
// ============================================================================

#[test]
#[ignore = "Covered transitively: private, and every section that adds to the \
            vec runs it."]
fn test_a_redoubt_vec_maybe_grown_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::extend_from_mut_slice
// ============================================================================

/// A vec extended is found while the vec holds it.
#[test]
fn test_a_redoubt_vec_extended_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtVec::<u8>::new();
        capture(|| held.extend_from_mut_slice(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec extended, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// A vec extended to one size, and let go.
///
/// Appended rather than replaced, so the vec reallocates on the way up rather
/// than being sized once, and what the sweep asks about is the blocks it
/// outgrew.
macro_rules! a_redoubt_vec_extended {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut sources: Vec<Vec<u8>> = (0..($of / SECRET.len()).max(1))
                .map(|_| {
                    let mut source = vec![0_u8; SECRET.len()];

                    giving(&mut source);

                    source
                })
                .collect();

            forensics!({
                let mut held = RedoubtVec::<u8>::new();

                capture(|| {
                    for source in &mut sources {
                        held.extend_from_mut_slice(source);
                    }
                });

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
            });

            drop(core::hint::black_box(sources));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec extended to {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_32_leaves_nothing, 32);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_64_leaves_nothing, 64);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_128_leaves_nothing, 128);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_512_leaves_nothing, 512);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_1024_leaves_nothing, 1024);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_4096_leaves_nothing, 4096);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_8192_leaves_nothing, 8192);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_16384_leaves_nothing, 16384);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_32768_leaves_nothing, 32768);
a_redoubt_vec_extended!(test_a_redoubt_vec_extended_to_65536_leaves_nothing, 65536);

// ============================================================================
// RedoubtVec::replace_from_mut_slice
// ============================================================================

/// A vec replaced is found while the vec holds it.
#[test]
fn test_a_redoubt_vec_replaced_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut held = RedoubtVec::<u8>::new();
        capture(|| held.replace_from_mut_slice(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec replaced, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// A vec replaced at one size, and let go.
///
/// The vec grows to hold the slice, copies it in, zeroizes the source, and is
/// zeroized itself on the way out. Nothing of the secret is supposed to
/// outlive the call.
macro_rules! a_redoubt_vec_replaced {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut held = RedoubtVec::<u8>::new();
                capture(|| held.replace_from_mut_slice(&mut source));

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
                &format!("a vec replaced of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_32_leaves_nothing, 32);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_64_leaves_nothing, 64);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_128_leaves_nothing, 128);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_512_leaves_nothing, 512);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_1024_leaves_nothing, 1024);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_4096_leaves_nothing, 4096);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_8192_leaves_nothing, 8192);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_16384_leaves_nothing, 16384);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_32768_leaves_nothing, 32768);
a_redoubt_vec_replaced!(test_a_redoubt_vec_replaced_of_65536_leaves_nothing, 65536);

// ============================================================================
// RedoubtVec::drain_value
// ============================================================================

fn wide_values(of: usize) -> Vec<u128> {
    let mut values = vec![0_u128; (of / core::mem::size_of::<u128>()).max(2)];

    // SAFETY: a `u128` has no invalid bit pattern, and the byte view covers
    // exactly the allocation `values` owns.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            values.as_mut_ptr().cast::<u8>(),
            values.len() * core::mem::size_of::<u128>(),
        )
    };

    giving(bytes);

    values
}

#[test]
fn test_a_redoubt_vec_drained_into_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = wide_values(SECRET.len());

    forensics!({
        let mut held = RedoubtVec::<u128>::new();

        capture(|| {
            for one in &mut source {
                held.drain_value(one);
            }
        });

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec drained into, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

macro_rules! a_redoubt_vec_drained_into {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = wide_values($of);

            forensics!({
                let mut held = RedoubtVec::<u128>::new();

                capture(|| {
                    for one in &mut source {
                        held.drain_value(one);
                    }
                });

                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a vec drained into to {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_vec_drained_into!(test_a_redoubt_vec_drained_into_to_32_leaves_nothing, 32);
a_redoubt_vec_drained_into!(test_a_redoubt_vec_drained_into_to_64_leaves_nothing, 64);
a_redoubt_vec_drained_into!(test_a_redoubt_vec_drained_into_to_128_leaves_nothing, 128);
a_redoubt_vec_drained_into!(test_a_redoubt_vec_drained_into_to_512_leaves_nothing, 512);
a_redoubt_vec_drained_into!(test_a_redoubt_vec_drained_into_to_1024_leaves_nothing, 1024);
a_redoubt_vec_drained_into!(test_a_redoubt_vec_drained_into_to_4096_leaves_nothing, 4096);
a_redoubt_vec_drained_into!(test_a_redoubt_vec_drained_into_to_8192_leaves_nothing, 8192);
a_redoubt_vec_drained_into!(
    test_a_redoubt_vec_drained_into_to_16384_leaves_nothing,
    16384
);
a_redoubt_vec_drained_into!(
    test_a_redoubt_vec_drained_into_to_32768_leaves_nothing,
    32768
);
a_redoubt_vec_drained_into!(
    test_a_redoubt_vec_drained_into_to_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtVec::clear
// ============================================================================

#[test]
#[ignore = "TODO: it removes the secret, and nothing measures it yet."]
fn test_a_redoubt_vec_cleared_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::as_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_vec_as_a_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::as_mut_slice
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_vec_as_a_mut_slice_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::as_vec
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_vec_as_a_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::as_mut_vec
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_vec_as_a_mut_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec::default_init_to_size
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes defaults."]
fn test_a_redoubt_vec_initialised_to_a_size_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec: Default
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty container."]
fn test_a_default_redoubt_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec: Deref
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_dereferencing_a_redoubt_vec_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtVec: DerefMut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_mutably_dereferencing_a_redoubt_vec_leaves_nothing() {
    // Intentionally empty.
}
