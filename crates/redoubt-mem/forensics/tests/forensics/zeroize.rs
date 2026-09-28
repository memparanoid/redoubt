// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Both backends are measured here, each wiping and letting go in the same
//! function, as a caller does: a write the optimizer proved dead would leave
//! the secret in the block or in the frame, and nothing in the test reads it
//! back to keep the write alive.

use redoubt_asm::Backend;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_mem_core::{copy_nonoverlapping, zeroize, zeroize_with_backend};

use crate::support::needles::{SECRET, backwards};
use crate::support::{is_found, leaves_nothing};

fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

fn a_box<const N: usize>() -> Box<[u8; N]> {
    let mut boxed = Box::new([0_u8; N]);

    giving(&mut boxed[..]);

    boxed
}

macro_rules! wipe {
    (default, $dst:expr, $count:expr) => {
        zeroize($dst, $count)
    };
    ($backend:expr, $dst:expr, $count:expr) => {
        zeroize_with_backend($backend, $dst, $count)
    };
}

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

macro_rules! test_zeroizing_a_box_and_letting_it_go_leaves_nothing {
    ($name:ident, $how:tt, $len:literal) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let held = a_box::<$len>();

            forensics!({
                capture(|| {
                    let mut held = held;

                    // SAFETY: the box is writable for its own length, and
                    // every byte zero is a `u8`.
                    unsafe { wipe!($how, held.as_mut_ptr(), $len) };
                });
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                "nothing held yet",
                &report_after,
                concat!("a box of ", $len, " zeroized and let go"),
            );

            Ok(())
        }
    };
}

macro_rules! test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing {
    ($name:ident, $how:tt, $len:literal) => {
        #[redoubt_forensics::test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            forensics!({
                capture(|| {
                    let mut held = [0_u8; $len];

                    giving(&mut held);

                    // SAFETY: the array is writable for its own length, and
                    // every byte zero is a `u8`.
                    unsafe { wipe!($how, held.as_mut_ptr(), $len) };
                });
            });

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                "nothing held yet",
                &report_after,
                concat!("an array of ", $len, " zeroized and let go with its frame"),
            );

            Ok(())
        }
    };
}

// ============================================================================
// zeroize
// ============================================================================

test_a_box_let_go_is_found!(test_a_box_of_32_let_go_is_found, 32);
test_a_box_let_go_is_found!(test_a_box_of_4096_let_go_is_found, 4096);
test_an_array_let_go_with_its_frame_is_found!(
    test_an_array_of_32_let_go_with_its_frame_is_found,
    32
);
test_an_array_let_go_with_its_frame_is_found!(
    test_an_array_of_4096_let_go_with_its_frame_is_found,
    4096
);

test_zeroizing_a_box_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_box_of_32_and_letting_it_go_leaves_nothing,
    default,
    32
);
test_zeroizing_a_box_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_box_of_4096_and_letting_it_go_leaves_nothing,
    default,
    4096
);
test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing!(
    test_zeroizing_an_array_of_32_and_letting_its_frame_go_leaves_nothing,
    default,
    32
);
test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing!(
    test_zeroizing_an_array_of_4096_and_letting_its_frame_go_leaves_nothing,
    default,
    4096
);

// ============================================================================
// zeroize_with_backend
// ============================================================================

test_zeroizing_a_box_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_box_of_32_through_rust_and_letting_it_go_leaves_nothing,
    (Backend::Rust),
    32
);
test_zeroizing_a_box_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_box_of_4096_through_rust_and_letting_it_go_leaves_nothing,
    (Backend::Rust),
    4096
);
test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing!(
    test_zeroizing_an_array_of_32_through_rust_and_letting_its_frame_go_leaves_nothing,
    (Backend::Rust),
    32
);
test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing!(
    test_zeroizing_an_array_of_4096_through_rust_and_letting_its_frame_go_leaves_nothing,
    (Backend::Rust),
    4096
);
test_zeroizing_a_box_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_box_of_32_through_auto_and_letting_it_go_leaves_nothing,
    (Backend::Auto),
    32
);
test_zeroizing_a_box_and_letting_it_go_leaves_nothing!(
    test_zeroizing_a_box_of_4096_through_auto_and_letting_it_go_leaves_nothing,
    (Backend::Auto),
    4096
);
test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing!(
    test_zeroizing_an_array_of_32_through_auto_and_letting_its_frame_go_leaves_nothing,
    (Backend::Auto),
    32
);
test_zeroizing_an_array_and_letting_its_frame_go_leaves_nothing!(
    test_zeroizing_an_array_of_4096_through_auto_and_letting_its_frame_go_leaves_nothing,
    (Backend::Auto),
    4096
);
