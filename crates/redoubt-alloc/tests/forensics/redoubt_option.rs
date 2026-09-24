// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::{RedoubtOption, RedoubtVec};
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::support::needles::{SECRET, backwards};
use crate::support::{Block, giving, hold_on, is_found, leaves_nothing, let_go};

// ============================================================================
// RedoubtOption::drop
// ============================================================================

/// An option dropped at one size.
macro_rules! a_redoubt_option_dropped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut inner = RedoubtVec::<u8>::new();
                inner.replace_from_mut_slice(&mut source);

                let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
                held.replace(&mut inner);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| drop(held));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(inner);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an option dropped of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_32_leaves_nothing, 32);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_64_leaves_nothing, 64);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_128_leaves_nothing, 128);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_512_leaves_nothing, 512);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_1024_leaves_nothing, 1024);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_4096_leaves_nothing, 4096);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_8192_leaves_nothing, 8192);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_16384_leaves_nothing, 16384);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_32768_leaves_nothing, 32768);
a_redoubt_option_dropped!(test_a_redoubt_option_dropped_of_65536_leaves_nothing, 65536);

// ============================================================================
// RedoubtOption: ownership
// ============================================================================

/// An option given away is found while whoever took it is holding it.
#[test]
fn test_a_redoubt_option_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut inner = RedoubtVec::<u8>::new();
        inner.replace_from_mut_slice(&mut source);

        let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
        held.replace(&mut inner);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation. See the header.
        drop(inner);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an option given away, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// An option given away at one size.
///
/// One container deep: what is given away is the option, and what it holds is
/// a vec that is itself a pointer.
macro_rules! a_redoubt_option_given_away {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut inner = RedoubtVec::<u8>::new();
                inner.replace_from_mut_slice(&mut source);

                let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
                held.replace(&mut inner);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| let_go(held));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(inner);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an option given away of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_option_given_away!(test_a_redoubt_option_given_away_of_32_leaves_nothing, 32);
a_redoubt_option_given_away!(test_a_redoubt_option_given_away_of_64_leaves_nothing, 64);
a_redoubt_option_given_away!(test_a_redoubt_option_given_away_of_128_leaves_nothing, 128);
a_redoubt_option_given_away!(test_a_redoubt_option_given_away_of_512_leaves_nothing, 512);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_1024_leaves_nothing,
    1024
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_4096_leaves_nothing,
    4096
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_8192_leaves_nothing,
    8192
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_16384_leaves_nothing,
    16384
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_32768_leaves_nothing,
    32768
);
a_redoubt_option_given_away!(
    test_a_redoubt_option_given_away_of_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtOption::as_ref
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_option_as_a_ref_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtOption::as_mut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_option_as_a_mut_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtOption::replace
// ============================================================================

/// A vec put inside an option is found while the option holds it.
#[test]
fn test_a_redoubt_option_replaced_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source = vec![0_u8; SECRET.len()];

    giving(&mut source);

    forensics!({
        let mut inner = RedoubtVec::<u8>::new();
        inner.replace_from_mut_slice(&mut source);

        let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
        capture(|| held.replace(&mut inner));

        core::mem::forget(held);

        drop(inner);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an option replaced, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// An option filled at one size, and let go.
///
/// `replace` has to swap the value into place, which leaves a transit
/// temporary on the stack while it does — and that temporary is in the window
/// the capture copies.
macro_rules! a_redoubt_option_replaced {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = vec![0_u8; $of];

            giving(&mut source);

            forensics!({
                let mut inner = RedoubtVec::<u8>::new();
                inner.replace_from_mut_slice(&mut source);

                let mut held = RedoubtOption::<RedoubtVec<u8>>::default();
                capture(|| held.replace(&mut inner));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation. See the header.
                drop(held);
                drop(inner);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("an option replaced of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_32_leaves_nothing, 32);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_64_leaves_nothing, 64);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_128_leaves_nothing, 128);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_512_leaves_nothing, 512);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_1024_leaves_nothing, 1024);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_4096_leaves_nothing, 4096);
a_redoubt_option_replaced!(test_a_redoubt_option_replaced_of_8192_leaves_nothing, 8192);
a_redoubt_option_replaced!(
    test_a_redoubt_option_replaced_of_16384_leaves_nothing,
    16384
);
a_redoubt_option_replaced!(
    test_a_redoubt_option_replaced_of_32768_leaves_nothing,
    32768
);
a_redoubt_option_replaced!(
    test_a_redoubt_option_replaced_of_65536_leaves_nothing,
    65536
);

#[test]
fn test_a_redoubt_option_of_a_block_replaced_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut source: Box<Block> = Box::new([0; SECRET.len()]);

    giving(&mut source[..]);

    forensics!({
        let mut held = Box::new(RedoubtOption::<Block>::default());
        capture(|| held.replace(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "an option of a block replaced, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

#[test]
fn test_a_redoubt_option_of_a_block_replaced_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source: Box<Block> = Box::new([0; SECRET.len()]);

    giving(&mut source[..]);

    forensics!({
        let mut held = Box::new(RedoubtOption::<Block>::default());
        capture(|| held.replace(&mut source));

        held.fast_zeroize();
    });

    drop(core::hint::black_box(source));

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "an option of a block replaced",
    );

    Ok(())
}

// ============================================================================
// RedoubtOption::is_some
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads whether there is a value."]
fn test_whether_a_redoubt_option_is_some_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtOption::is_none
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads whether there is a value."]
fn test_whether_a_redoubt_option_is_none_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtOption::as_option
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_option_as_an_option_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtOption::as_mut_option
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_option_as_a_mut_option_leaves_nothing() {
    // Intentionally empty.
}
