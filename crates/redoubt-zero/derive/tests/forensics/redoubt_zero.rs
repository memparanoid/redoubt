// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, capture, forensics, is_found, leaves_nothing};
use redoubt_zero_core::{FastZeroizable, ZeroizationProbe};
use redoubt_zero_derive::RedoubtZero;

use crate::support::needles::{NEEDLE, backwards};
use crate::support::{giving, hold_on, let_go};

const WIDE: usize = 8 * NEEDLE.len();

#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
struct Pair {
    bytes: Vec<u8>,
    boxed: Box<[u8; 16]>,
}

#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
enum Custody {
    Bytes(Vec<u8>),
    Boxed { boxed: Box<[u8; 16]>, id: u64 },
}

fn bytes() -> Vec<u8> {
    let mut bytes = vec![0_u8; WIDE];

    giving(&mut bytes);

    bytes
}

fn boxed() -> Box<[u8; 16]> {
    let mut boxed = Box::new([0_u8; 16]);

    giving(&mut *boxed);

    boxed
}

fn pair() -> Pair {
    Pair {
        bytes: bytes(),
        boxed: boxed(),
    }
}

fn custody_of_bytes() -> Custody {
    Custody::Bytes(bytes())
}

fn custody_boxed() -> Custody {
    Custody::Boxed {
        boxed: boxed(),
        id: 7,
    }
}

// ============================================================================
// fast_zeroize
// ============================================================================

macro_rules! zeroizing_leaves_nothing {
    ($($name:ident: $what:literal => $fill:expr;)*) => {
        $(
            #[redoubt_forensics::test]
            fn $name() -> Result<(), AnyError> {
                let mut watch = Forensics::watching(&backwards())?;

                let report_before = watch.snapshot()?;

                let mut held = $fill();

                forensics!({
                    capture(|| held.fast_zeroize());

                    // Forgotten and not emptied: emptying it is the operation's.
                    core::mem::forget(held);
                });

                leaves_nothing(&report_before, &watch.snapshot()?, $what);

                Ok(())
            }
        )*
    };
}

zeroizing_leaves_nothing! {
    test_zeroizing_a_struct_leaves_nothing: "a struct zeroized" => pair;
    test_zeroizing_an_enum_of_bytes_leaves_nothing: "an enum of bytes zeroized" => custody_of_bytes;
    test_zeroizing_an_enum_with_a_box_leaves_nothing: "an enum with a box zeroized" => custody_boxed;
}

// ============================================================================
// is_zeroized
// ============================================================================

macro_rules! probing_leaves_nothing {
    ($($name:ident: $what:literal => $fill:expr;)*) => {
        $(
            #[redoubt_forensics::test]
            fn $name() -> Result<(), AnyError> {
                let mut watch = Forensics::watching(&backwards())?;

                let report_before = watch.snapshot()?;

                let held = $fill();

                forensics!({
                    capture(|| core::hint::black_box(held.is_zeroized()));

                    // CORRECTNESS: after the capture. A call made before it writes over
                    // the stack and the registers the operation left, and then the absence
                    // below is about that call and not about the operation.
                    drop(held);
                });

                leaves_nothing(&report_before, &watch.snapshot()?, $what);

                Ok(())
            }
        )*
    };
}

probing_leaves_nothing! {
    test_probing_a_struct_leaves_nothing: "a struct probed" => pair;
    test_probing_an_enum_of_bytes_leaves_nothing: "an enum of bytes probed" => custody_of_bytes;
    test_probing_an_enum_with_a_box_leaves_nothing: "an enum with a box probed" => custody_boxed;
}

// ============================================================================
// Drop
// ============================================================================

macro_rules! dropping_leaves_nothing {
    ($($name:ident: $what:literal => $fill:expr;)*) => {
        $(
            #[redoubt_forensics::test]
            fn $name() -> Result<(), AnyError> {
                let mut watch = Forensics::watching(&backwards())?;

                let report_before = watch.snapshot()?;

                let held = $fill();

                forensics!({
                    // CORRECTNESS: inside the capture, because this is the operation. What
                    // the section measures is whether it leaves a copy in the registers or
                    // the stack it used itself. What it writes over is whatever ran before
                    // it, which has a section of its own.
                    capture(|| drop(held));
                });

                leaves_nothing(&report_before, &watch.snapshot()?, $what);

                Ok(())
            }
        )*
    };
}

dropping_leaves_nothing! {
    test_dropping_a_struct_leaves_nothing: "a struct dropped" => pair;
    test_dropping_an_enum_of_bytes_leaves_nothing: "an enum of bytes dropped" => custody_of_bytes;
    test_dropping_an_enum_with_a_box_leaves_nothing: "an enum with a box dropped" => custody_boxed;
}

// ============================================================================
// ownership
// ============================================================================

macro_rules! given_away_is_found {
    ($($name:ident: $what:literal => $fill:expr;)*) => {
        $(
            #[redoubt_forensics::test]
            fn $name() -> Result<(), AnyError> {
                let held = $fill();
                let mut watch = Forensics::watching(&backwards())?;

                forensics!({
                    // CORRECTNESS: inside the capture, because this is the operation. What
                    // the section measures is whether it leaves a copy in the registers or
                    // the stack it used itself. What it writes over is whatever ran before
                    // it, which has a section of its own.
                    capture(|| hold_on(held));
                });

                is_found(&watch.snapshot()?, $what);

                Ok(())
            }
        )*
    };
}

given_away_is_found! {
    test_a_struct_given_away_is_found_while_it_is_held: "a struct given away, and kept" => pair;
    test_an_enum_of_bytes_given_away_is_found_while_it_is_held:
        "an enum of bytes given away, and kept" => custody_of_bytes;
    test_an_enum_with_a_box_given_away_is_found_while_it_is_held:
        "an enum with a box given away, and kept" => custody_boxed;
}

macro_rules! given_away_leaves_nothing {
    ($($name:ident: $what:literal => $fill:expr;)*) => {
        $(
            #[redoubt_forensics::test]
            fn $name() -> Result<(), AnyError> {
                let mut watch = Forensics::watching(&backwards())?;

                let report_before = watch.snapshot()?;

                let held = $fill();

                forensics!({
                    // CORRECTNESS: inside the capture, because this is the operation. What
                    // the section measures is whether it leaves a copy in the registers or
                    // the stack it used itself. What it writes over is whatever ran before
                    // it, which has a section of its own.
                    capture(|| let_go(held));
                });

                leaves_nothing(&report_before, &watch.snapshot()?, $what);

                Ok(())
            }
        )*
    };
}

given_away_leaves_nothing! {
    test_a_struct_given_away_leaves_nothing: "a struct given away" => pair;
    test_an_enum_of_bytes_given_away_leaves_nothing: "an enum of bytes given away" => custody_of_bytes;
    test_an_enum_with_a_box_given_away_leaves_nothing:
        "an enum with a box given away" => custody_boxed;
}
