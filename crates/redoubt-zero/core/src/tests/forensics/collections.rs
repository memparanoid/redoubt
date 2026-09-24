// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Every removal here rests on the guards' presences, which find the same
//! fixture held.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::collections::{
    collection_zeroed, slice_fast_zeroize, to_fast_zeroizable_dyn_mut,
    to_zeroization_probe_dyn_ref, vec_fast_zeroize, zeroize_collection,
};
use crate::{FastZeroizable, ZeroizationProbe};

use crate::tests::forensics::support::needles::{SECRET, backwards};
use crate::tests::forensics::support::{giving, is_found, leaves_nothing};

/// A secret a `String` can hold: every byte ASCII, none repeated.
const TEXT: &[u8; 32] = b"q7Xv2Lp9Rz4Nb8Kt1Mw6Hc3Yf5Gd0SjA";

fn text_backwards() -> Vec<u8> {
    TEXT.iter().rev().copied().collect()
}

fn a_box() -> Box<[u8; 32]> {
    let mut boxed = Box::new([0_u8; 32]);

    giving(&mut boxed[..]);

    boxed
}

fn a_vec(of: usize) -> Vec<u8> {
    let mut vec = vec![0_u8; of];

    giving(&mut vec);

    vec
}

fn a_string() -> String {
    let mut string = String::with_capacity(TEXT.len());

    // SAFETY: every byte written below is ASCII, so what the string holds
    // spells UTF-8.
    let bytes = unsafe { string.as_mut_vec() };

    bytes.resize(TEXT.len(), 0);

    // SAFETY: a constant and a heap block are different allocations, both as
    // long as the text.
    unsafe { redoubt_mem::copy_nonoverlapping(TEXT.as_ptr(), bytes.as_mut_ptr(), TEXT.len()) };

    string
}

// ============================================================================
// to_fast_zeroizable_dyn_mut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it turns a reference into a trait object."]
fn test_a_zeroizable_seen_as_a_trait_object_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// to_zeroization_probe_dyn_ref
// ============================================================================

#[test]
#[ignore = "Reads no secret: it turns a reference into a trait object."]
fn test_a_probe_seen_as_a_trait_object_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// zeroize_collection
// ============================================================================

#[test]
fn test_zeroizing_a_collection_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut first = a_box();
    let mut second = a_vec(SECRET.len());

    forensics!({
        let mut fields: [&mut dyn FastZeroizable; 2] = [
            to_fast_zeroizable_dyn_mut(&mut first),
            to_fast_zeroizable_dyn_mut(&mut second),
        ];

        capture(|| zeroize_collection(&mut fields.iter_mut().map(|field| &mut **field)));
    });

    drop(core::hint::black_box((first, second)));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a collection zeroized");

    Ok(())
}

// ============================================================================
// collection_zeroed
// ============================================================================

#[test]
fn test_a_collection_probed_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let first = a_box();
    let second = a_vec(SECRET.len());

    forensics!({
        let fields: [&dyn ZeroizationProbe; 2] = [
            to_zeroization_probe_dyn_ref(&first),
            to_zeroization_probe_dyn_ref(&second),
        ];

        capture(|| core::hint::black_box(collection_zeroed(&mut fields.into_iter())));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a collection probed, and kept");

    drop(core::hint::black_box((first, second)));

    Ok(())
}

#[test]
fn test_probing_a_collection_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut first = a_box();
    let mut second = a_vec(SECRET.len());

    forensics!({
        let fields: [&dyn ZeroizationProbe; 2] = [
            to_zeroization_probe_dyn_ref(&first),
            to_zeroization_probe_dyn_ref(&second),
        ];

        capture(|| core::hint::black_box(collection_zeroed(&mut fields.into_iter())));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        first.fast_zeroize();
        second.fast_zeroize();
    });

    drop(core::hint::black_box((first, second)));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a collection probed");

    Ok(())
}

// ============================================================================
// slice_fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_slice_in_bulk_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_box();

    forensics!({
        capture(|| slice_fast_zeroize(&mut held[..], true));
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a slice zeroized in bulk");

    Ok(())
}

#[test]
fn test_zeroizing_a_slice_one_element_at_a_time_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_box();

    forensics!({
        capture(|| slice_fast_zeroize(&mut held[..], false));
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "a slice zeroized one element at a time",
    );

    Ok(())
}

// ============================================================================
// [T]::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_slice_of_bytes_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_box();

    forensics!({
        let slice: &mut [u8] = &mut held[..];

        capture(|| slice.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a slice of bytes zeroized");

    Ok(())
}

#[test]
fn test_zeroizing_a_slice_of_boxes_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = vec![a_box(), a_box()];

    forensics!({
        let slice: &mut [Box<[u8; 32]>] = &mut held[..];

        capture(|| slice.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a slice of boxes zeroized");

    Ok(())
}

// ============================================================================
// [T]::is_zeroized
// ============================================================================

#[test]
fn test_a_slice_probed_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let held = a_box();

    forensics!({
        let slice: &[u8] = &held[..];

        capture(|| core::hint::black_box(slice.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a slice probed, and kept");

    drop(core::hint::black_box(held));

    Ok(())
}

#[test]
fn test_probing_a_slice_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_box();

    forensics!({
        let slice: &[u8] = &held[..];

        capture(|| core::hint::black_box(slice.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        held.fast_zeroize();
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a slice probed");

    Ok(())
}

// ============================================================================
// [T; N]::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_an_array_of_bytes_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_box();

    forensics!({
        let array: &mut [u8; 32] = &mut held;

        capture(|| array.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array of bytes zeroized");

    Ok(())
}

#[test]
fn test_zeroizing_an_array_of_boxes_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = Box::new([a_box(), a_box()]);

    forensics!({
        let array: &mut [Box<[u8; 32]>; 2] = &mut held;

        capture(|| array.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array of boxes zeroized");

    Ok(())
}

// ============================================================================
// [T; N]::is_zeroized
// ============================================================================

#[test]
fn test_an_array_probed_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let held = a_box();

    forensics!({
        let array: &[u8; 32] = &held;

        capture(|| core::hint::black_box(array.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "an array probed, and kept");

    drop(core::hint::black_box(held));

    Ok(())
}

#[test]
fn test_probing_an_array_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_box();

    forensics!({
        let array: &[u8; 32] = &held;

        capture(|| core::hint::black_box(array.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        held.fast_zeroize();
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an array probed");

    Ok(())
}

// ============================================================================
// vec_fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_vec_in_bulk_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_vec(2 * SECRET.len());

    held.truncate(SECRET.len());

    forensics!({
        capture(|| vec_fast_zeroize(&mut held, true));
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a vec zeroized in bulk");

    Ok(())
}

#[test]
fn test_zeroizing_a_vec_one_element_at_a_time_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_vec(2 * SECRET.len());

    held.truncate(SECRET.len());

    forensics!({
        capture(|| vec_fast_zeroize(&mut held, false));
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(
        &report_before,
        &report_after,
        "a vec zeroized one element at a time",
    );

    Ok(())
}

// ============================================================================
// Vec<T>::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_vec_of_bytes_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_vec(2 * SECRET.len());

    held.truncate(SECRET.len());

    forensics!({
        capture(|| held.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a vec of bytes zeroized");

    Ok(())
}

#[test]
fn test_zeroizing_a_vec_of_boxes_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = vec![a_box(), a_box()];

    forensics!({
        capture(|| held.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a vec of boxes zeroized");

    Ok(())
}

// ============================================================================
// Vec<T>::is_zeroized
// ============================================================================

#[test]
fn test_a_vec_probed_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let held = a_vec(SECRET.len());

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a vec probed, and kept");

    drop(core::hint::black_box(held));

    Ok(())
}

#[test]
fn test_probing_a_vec_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_vec(SECRET.len());

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        held.fast_zeroize();
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a vec probed");

    Ok(())
}

// ============================================================================
// String::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_string_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_string();

    forensics!({
        capture(|| held.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a string zeroized");

    Ok(())
}

// ============================================================================
// String::is_zeroized
// ============================================================================

#[test]
fn test_a_string_probed_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let held = a_string();

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string probed, and kept");

    drop(core::hint::black_box(held));

    Ok(())
}

#[test]
fn test_probing_a_string_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&text_backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_string();

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        held.fast_zeroize();
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a string probed");

    Ok(())
}

// ============================================================================
// Box<T>::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_a_box_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_box();

    forensics!({
        capture(|| held.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a box zeroized");

    Ok(())
}

// ============================================================================
// Box<T>::is_zeroized
// ============================================================================

#[test]
fn test_a_box_probed_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let held = a_box();

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a box probed, and kept");

    drop(core::hint::black_box(held));

    Ok(())
}

#[test]
fn test_probing_a_box_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held = a_box();

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        held.fast_zeroize();
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "a box probed");

    Ok(())
}

// ============================================================================
// Option<T>::fast_zeroize
// ============================================================================

#[test]
fn test_zeroizing_an_option_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held: Box<Option<[u8; 32]>> = Box::new(Some([0_u8; 32]));

    if let Some(value) = held.as_mut() {
        giving(value);
    }

    forensics!({
        capture(|| held.fast_zeroize());
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an option zeroized");

    Ok(())
}

// ============================================================================
// Option<T>::is_zeroized
// ============================================================================

#[test]
fn test_an_option_probed_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let mut held: Box<Option<[u8; 32]>> = Box::new(Some([0_u8; 32]));

    if let Some(value) = held.as_mut() {
        giving(value);
    }

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));
    });

    let report = watch.snapshot()?;

    is_found(&report, "an option probed, and kept");

    drop(core::hint::black_box(held));

    Ok(())
}

#[test]
fn test_probing_an_option_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut held: Box<Option<[u8; 32]>> = Box::new(Some([0_u8; 32]));

    if let Some(value) = held.as_mut() {
        giving(value);
    }

    forensics!({
        capture(|| core::hint::black_box(held.is_zeroized()));

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        held.fast_zeroize();
    });

    drop(core::hint::black_box(held));

    let report_after = watch.snapshot()?;

    leaves_nothing(&report_before, &report_after, "an option probed");

    Ok(())
}
