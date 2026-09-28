// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Each wiper runs and lets go in the same function, as a caller does: a write
//! the optimizer proved dead would leave the secret in the block or in the
//! frame, and nothing in the test reads it back to keep the write alive.

use redoubt_forensics::{AnyError, Forensics, QUIET, Report, capture, forensics};
use redoubt_util::{
    fast_zeroize_slice, fast_zeroize_vec, zeroize_primitive, zeroize_spare_capacity,
};

const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

fn backwards() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

fn a_box<const N: usize>() -> Box<[u8; N]> {
    let mut boxed = Box::new([0_u8; N]);

    giving(&mut boxed[..]);

    boxed
}

fn a_vec_with_spare(of: usize) -> Vec<u8> {
    let mut vec = vec![0_u8; 2 * of];

    giving(&mut vec);

    vec.truncate(of);

    vec
}

fn a_vec_all_spare(of: usize) -> Vec<u8> {
    let mut vec = vec![0_u8; of];

    giving(&mut vec);

    vec.truncate(0);

    vec
}

fn is_found(report: &Report, what: &str) {
    println!();
    report.summary(what);
    println!();

    assert!(
        report.found,
        "the sweep does not reach {what}, so every absence below it is the \
         instrument standing where the evidence is: {report}"
    );
}

fn leaves_nothing(report_before: &Report, report_after: &Report, what: &str) {
    println!();
    report_before.summary("nothing held yet");
    report_after.summary_against(report_before, what);
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the whole secret survived {what}: {report_after}"
    );

    assert!(
        report_after.widest <= QUIET,
        "a run of {} bytes survived {what}, and {QUIET} is what memory has by \
         accident: {report_after}",
        report_after.widest,
    );

    let delta = report_after.against(report_before);

    assert!(delta.is_noise(), "{what} moved the score: {delta}");
}

// ============================================================================
// planting
// ============================================================================

macro_rules! test_a_box_let_go_is_found {
    ($name:ident, $len:literal) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let held = a_box::<$len>();

            forensics!({
                capture(|| drop(held));
            });

            let report = watch.snapshot()?;

            is_found(&report, concat!("a box of ", $len, " let go"));

            Ok(())
        }
    };
}

test_a_box_let_go_is_found!(test_a_box_of_32_let_go_is_found, 32);
test_a_box_let_go_is_found!(test_a_box_of_4096_let_go_is_found, 4096);

macro_rules! test_an_array_let_go_with_its_frame_is_found {
    ($name:ident, $len:literal) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            forensics!({
                capture(|| {
                    let mut held = [0_u8; $len];

                    giving(&mut held);
                });
            });

            let report = watch.snapshot()?;

            is_found(
                &report,
                concat!("an array of ", $len, " let go with its frame"),
            );

            Ok(())
        }
    };
}

test_an_array_let_go_with_its_frame_is_found!(
    test_an_array_of_32_let_go_with_its_frame_is_found,
    32
);
test_an_array_let_go_with_its_frame_is_found!(
    test_an_array_of_4096_let_go_with_its_frame_is_found,
    4096
);

macro_rules! test_a_vec_let_go_is_found {
    ($name:ident, $fixture:ident, $len:literal, $what:literal) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let held = $fixture($len);

            forensics!({
                capture(|| drop(held));
            });

            let report = watch.snapshot()?;

            is_found(&report, $what);

            Ok(())
        }
    };
}

test_a_vec_let_go_is_found!(
    test_a_vec_of_32_with_as_much_spare_let_go_is_found,
    a_vec_with_spare,
    32,
    "a vec of 32 with as much spare, let go"
);
test_a_vec_let_go_is_found!(
    test_a_vec_of_4096_with_as_much_spare_let_go_is_found,
    a_vec_with_spare,
    4096,
    "a vec of 4096 with as much spare, let go"
);
test_a_vec_let_go_is_found!(
    test_a_vec_truncated_from_32_to_nothing_let_go_is_found,
    a_vec_all_spare,
    32,
    "a vec truncated from 32 to nothing, let go"
);
test_a_vec_let_go_is_found!(
    test_a_vec_truncated_from_4096_to_nothing_let_go_is_found,
    a_vec_all_spare,
    4096,
    "a vec truncated from 4096 to nothing, let go"
);

// ============================================================================
// zeroize_primitive
// ============================================================================

#[redoubt_forensics::test]
fn test_zeroizing_a_primitive_and_letting_it_go_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let held = a_box::<32>();

    forensics!({
        capture(|| {
            let mut held = held;

            zeroize_primitive(&mut *held);
        });
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "an array of 32 zeroized as a primitive and let go",
    );

    Ok(())
}

// ============================================================================
// fast_zeroize_slice
// ============================================================================

macro_rules! test_zeroizing_a_boxed_slice_and_letting_it_go_leaves_nothing {
    ($name:ident, $len:literal) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let held = a_box::<$len>();

            forensics!({
                capture(|| {
                    let mut held = held;

                    // SAFETY: every byte zero is a `u8`.
                    unsafe { fast_zeroize_slice(&mut held[..]) };
                });
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                concat!("a box of ", $len, " zeroized and let go"),
            );

            Ok(())
        }
    };
}

test_zeroizing_a_boxed_slice_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_box_of_32_and_letting_it_go_leaves_nothing,
    32
);
test_zeroizing_a_boxed_slice_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_box_of_4096_and_letting_it_go_leaves_nothing,
    4096
);

macro_rules! test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing {
    ($name:ident, $len:literal) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            forensics!({
                capture(|| {
                    let mut held = [0_u8; $len];

                    giving(&mut held);

                    // SAFETY: every byte zero is a `u8`.
                    unsafe { fast_zeroize_slice(&mut held) };
                });
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                concat!("an array of ", $len, " zeroized and let go with its frame"),
            );

            Ok(())
        }
    };
}

test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing!(
    test_zeroizing_an_array_of_32_and_letting_its_frame_go_leaves_nothing,
    32
);
test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing!(
    test_zeroizing_an_array_of_4096_and_letting_its_frame_go_leaves_nothing,
    4096
);

// ============================================================================
// fast_zeroize_vec
// ============================================================================

macro_rules! test_zeroizing_a_vec_and_letting_it_go_leaves_nothing {
    ($name:ident, $len:literal) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let held = a_vec_with_spare($len);

            forensics!({
                capture(|| {
                    let mut held = held;

                    // SAFETY: every byte zero is a `u8`.
                    unsafe { fast_zeroize_vec(&mut held) };
                });
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                concat!(
                    "a vec of ",
                    $len,
                    " with as much spare, zeroized and let go"
                ),
            );

            Ok(())
        }
    };
}

test_zeroizing_a_vec_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_vec_of_32_with_as_much_spare_and_letting_it_go_leaves_nothing,
    32
);
test_zeroizing_a_vec_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_vec_of_4096_with_as_much_spare_and_letting_it_go_leaves_nothing,
    4096
);

// ============================================================================
// zeroize_spare_capacity
// ============================================================================

macro_rules! test_zeroizing_the_spare_and_letting_the_vec_go_leaves_nothing {
    ($name:ident, $len:literal) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let held = a_vec_all_spare($len);

            forensics!({
                capture(|| {
                    let mut held = held;

                    zeroize_spare_capacity(&mut held);
                });
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                concat!(
                    "a vec truncated from ",
                    $len,
                    " to nothing, its spare zeroized and let go"
                ),
            );

            Ok(())
        }
    };
}

test_zeroizing_the_spare_and_letting_the_vec_go_leaves_nothing!(
    test_zeroizing_the_spare_of_a_vec_truncated_from_32_and_letting_it_go_leaves_nothing,
    32
);
test_zeroizing_the_spare_and_letting_the_vec_go_leaves_nothing!(
    test_zeroizing_the_spare_of_a_vec_truncated_from_4096_and_letting_it_go_leaves_nothing,
    4096
);
