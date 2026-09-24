// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Both backends are measured here: the portable check reads one byte at a
//! time, volatile, and so makes a claim a sweep can hold it to.

use redoubt_asm::Backend;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use rstest::rstest;

use crate::copy_nonoverlapping;
use crate::utf8::{is_utf8, is_utf8_with_backend};

use crate::tests::forensics::support::{is_found, leaves_nothing, wipe};

/// Thirty-two bytes of UTF-8, every width among them, with a character boundary
/// at `BREAKS_AT`.
const TEXT: [u8; 32] = [
    0x71, 0x37, 0xC3, 0xB1, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80, 0x58, 0x76, 0xD0, 0x96, 0x7A,
    0x39, 0xC5, 0x91, 0xF0, 0x9F, 0x9C, 0x82, 0x52, 0x6B, 0x4C, 0x70, 0x34, 0x48, 0x63, 0x32, 0x57,
];

/// Where the refused text stops being UTF-8: the check reads what is before it
/// and nothing after.
const BREAKS_AT: usize = 16;

/// The needle, built from its last byte to its first and never turned around:
/// the forward bytes must not exist in this process.
fn text_backwards() -> Vec<u8> {
    TEXT.iter().rev().copied().collect()
}

/// What a check refused at `BREAKS_AT` reads, as a needle.
fn read_backwards() -> Vec<u8> {
    TEXT[..BREAKS_AT].iter().rev().copied().collect()
}

/// The text in a heap block, through the copy measured beside this file.
fn hold() -> Vec<u8> {
    let mut held = vec![0_u8; TEXT.len()];

    // SAFETY: a constant and a heap block are different allocations, and both
    // are as long as the text.
    unsafe { copy_nonoverlapping(TEXT.as_ptr(), held.as_mut_ptr(), TEXT.len()) };

    held
}

fn hold_broken() -> Vec<u8> {
    let mut held = hold();

    held[BREAKS_AT] = 0xFF;

    held
}

// ============================================================================
// is_utf8
// ============================================================================

#[test]
fn test_text_checked_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let text = hold();
    let answer: bool;

    forensics!({
        answer = capture(|| is_utf8(&text));
    });

    let report = watch.snapshot()?;

    is_found(&report, "text checked, left where it is held");

    assert!(answer, "the text is UTF-8");

    drop(core::hint::black_box(text));

    Ok(())
}

#[test]
fn test_checking_text_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut text = hold();
    let answer: bool;

    forensics!({
        answer = capture(|| is_utf8(&text));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut text);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, "nothing held yet", &report_after, "a check");

    assert!(answer, "the text is UTF-8");

    drop(core::hint::black_box(text));

    Ok(())
}

// ============================================================================
// is_utf8_with_backend
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_text_checked_through_a_backend_is_found_while_it_is_held(
    #[case] backend: Backend,
) -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let text = hold();
    let answer: bool;

    forensics!({
        answer = capture(|| is_utf8_with_backend(backend, &text));
    });

    let report = watch.snapshot()?;

    is_found(&report, "text checked, left where it is held");

    assert!(answer, "the text is UTF-8");

    drop(core::hint::black_box(text));

    Ok(())
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_text_refused_half_way_is_found_while_it_is_held(
    #[case] backend: Backend,
) -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&read_backwards())?;

    let text = hold_broken();
    let answer: bool;

    forensics!({
        answer = capture(|| is_utf8_with_backend(backend, &text));
    });

    let report = watch.snapshot()?;

    is_found(&report, "text refused half way, left where it is held");

    assert!(!answer, "the text is not UTF-8");

    drop(core::hint::black_box(text));

    Ok(())
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_checking_text_through_a_backend_leaves_nothing(
    #[case] backend: Backend,
) -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut text = hold();
    let answer: bool;

    forensics!({
        answer = capture(|| is_utf8_with_backend(backend, &text));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut text);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, "nothing held yet", &report_after, "a check");

    assert!(answer, "the text is UTF-8");

    drop(core::hint::black_box(text));

    Ok(())
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_checking_text_refused_half_way_leaves_nothing(
    #[case] backend: Backend,
) -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&read_backwards())?;

    let report_before = watch.snapshot()?;

    let mut text = hold_broken();
    let answer: bool;

    forensics!({
        answer = capture(|| is_utf8_with_backend(backend, &text));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut text);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &report_after,
        "a check refused half way",
    );

    assert!(!answer, "the text is not UTF-8");

    drop(core::hint::black_box(text));

    Ok(())
}
