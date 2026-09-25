// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Both backends are measured here. The portable check is not clean: it reads
//! one byte at a time and leaves the last it read in a register, and what is
//! asserted of it is that nothing wider than `QUIET` survives.

use redoubt_asm::Backend;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_mem_core::{copy_nonoverlapping, is_zeroized, is_zeroized_with_backend};
use rstest::rstest;

use crate::support::needles::{SECRET, backwards};
use crate::support::{is_found, leaves_nothing, wipe};

/// The secret in a heap block, through the copy measured beside this file.
fn hold() -> Vec<u8> {
    let mut held = vec![0_u8; SECRET.len()];

    // SAFETY: a constant and a heap block are different allocations, and both
    // are as long as the secret.
    unsafe { copy_nonoverlapping(SECRET.as_ptr(), held.as_mut_ptr(), SECRET.len()) };

    held
}

// ============================================================================
// is_zeroized
// ============================================================================

#[test]
fn test_bytes_probed_are_found_while_they_are_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let held = hold();
    let answer: bool;

    forensics!({
        answer = capture(|| is_zeroized(&held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "bytes probed, left where they are held");

    assert!(!answer, "the secret is not zeros");

    drop(core::hint::black_box(held));

    Ok(())
}

#[test]
fn test_probing_bytes_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = hold();
    let answer: bool;

    forensics!({
        answer = capture(|| is_zeroized(&held));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut held);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, "nothing held yet", &report_after, "a probe");

    assert!(!answer, "the secret is not zeros");

    drop(core::hint::black_box(held));

    Ok(())
}

// ============================================================================
// is_zeroized_with_backend
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_bytes_probed_through_a_backend_are_found_while_they_are_held(
    #[case] backend: Backend,
) -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let held = hold();
    let answer: bool;

    forensics!({
        answer = capture(|| is_zeroized_with_backend(backend, &held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "bytes probed, left where they are held");

    assert!(!answer, "the secret is not zeros");

    drop(core::hint::black_box(held));

    Ok(())
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_probing_bytes_through_a_backend_leaves_nothing(
    #[case] backend: Backend,
) -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = hold();
    let answer: bool;

    forensics!({
        answer = capture(|| is_zeroized_with_backend(backend, &held));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut held);
    });

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, "nothing held yet", &report_after, "a probe");

    assert!(!answer, "the secret is not zeros");

    drop(core::hint::black_box(held));

    Ok(())
}
