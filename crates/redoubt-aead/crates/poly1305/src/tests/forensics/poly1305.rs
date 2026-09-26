// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The state keeps its bytes in the struct. Where it is let go by value it
//! lives in the test's frame, as it does in a caller's: a box there would move
//! a pointer and measure the box.

use std::boxed::Box;

use redoubt_aead_core::consts::poly1305::{KEY_SIZE, TAG_SIZE};
use redoubt_asm::Backend;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::poly1305::{Poly1305, tag};

use crate::tests::forensics::support::{Watching, backwards, giving, is_found};

/// Thirty-two distinct bytes, so a run that extends did not extend by luck. The
/// high half is `s`, which the state keeps as it arrived.
const KEY: [u8; KEY_SIZE] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// Public, as the ciphertext an AEAD authenticates is, and so not watched.
const MESSAGE: &[u8; 70] =
    b"a message that is public, seventy bytes long, four blocks and a tail..";

/// `r` as the state holds it: five clamped limbs of twenty-six bits, cut after
/// the last byte that is not zero, which any empty memory would match.
///
/// `R`, `ACC`, `ACC_PADDED` and `TAG` were printed once by a generator, not
/// committed, that held the Rust backend and the assembly to the same bytes.
const R: [u8; 19] = [
    0x9E, 0x41, 0x17, 0x03, // limb 0 = 0x317_419E
    0x00, 0x16, 0xFC, 0x02, // limb 1 = 0x2FC_1600
    0x82, 0xC0, 0x46, 0x03, // limb 2 = 0x346_C082
    0x2A, 0x1C, 0xE0, 0x00, // limb 3 = 0xE0_1C2A
    0x52, 0xCE, 0x01, // limb 4 = 0x1_CE52
];

/// The accumulator once `MESSAGE`'s whole blocks are in, the tail still
/// buffered; cut the same way.
const ACC: [u8; 35] = [
    0x86, 0x34, 0x63, 0x02, 0x00, 0x00, 0x00, 0x00, // limb 0 = 0x263_3486
    0x1B, 0x55, 0x49, 0x02, 0x00, 0x00, 0x00, 0x00, // limb 1 = 0x249_551B
    0x21, 0xB2, 0xB4, 0x03, 0x00, 0x00, 0x00, 0x00, // limb 2 = 0x3B4_B221
    0xB7, 0xCE, 0x8F, 0x02, 0x00, 0x00, 0x00, 0x00, // limb 3 = 0x28F_CEB7
    0xE5, 0x99, 0xCD, // limb 4 = 0xCD_99E5
];

/// The accumulator once the tail is in too, padded to a block.
const ACC_PADDED: [u8; 36] = [
    0x45, 0xDE, 0x73, 0x02, 0x00, 0x00, 0x00, 0x00, // limb 0 = 0x273_DE45
    0xB5, 0xBB, 0xD3, 0x03, 0x00, 0x00, 0x00, 0x00, // limb 1 = 0x3D3_BBB5
    0x63, 0xD8, 0x50, 0x02, 0x00, 0x00, 0x00, 0x00, // limb 2 = 0x250_D863
    0xB5, 0x95, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x00, // limb 3 = 0x6D_95B5
    0xED, 0x7C, 0x0E, 0x02, // limb 4 = 0x20E_7CED
];

/// `MESSAGE`'s tag under `KEY`.
const TAG: [u8; TAG_SIZE] = [
    0x90, 0xF2, 0x02, 0xF9, 0x9A, 0xC5, 0x3B, 0xEC, 0x58, 0x0E, 0x44, 0x2E, 0xF8, 0xBD, 0xBA, 0x8A,
];

/// The key in a box, so no stack slot is left holding it.
fn a_key() -> Box<[u8; KEY_SIZE]> {
    let mut key = Box::new([0_u8; KEY_SIZE]);

    giving(&mut *key, &KEY);

    key
}

// ============================================================================
// Poly1305::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it is an empty state."]
fn test_making_one_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Poly1305::init
// ============================================================================

#[test]
fn test_what_init_wrote_is_found_while_the_state_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&R))?;

    let mut key = a_key();

    forensics!({
        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let poly = Box::leak(Box::new(Poly1305::new()));

        capture(|| poly.init(Backend::default(), &key));

        key.fast_zeroize();
    });

    is_found(&watch.snapshot()?, "a state keyed, and kept");

    Ok(())
}

#[test]
fn test_init_leaves_nothing() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[("key", &KEY), ("r", &R)])?;

    let mut key = a_key();

    forensics!({
        let mut poly = Poly1305::new();

        capture(|| poly.init(Backend::default(), &key));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The key and the state are the caller's.
        key.fast_zeroize();
        poly.fast_zeroize();
    });

    watching.none_left("init")?;

    Ok(())
}

// ============================================================================
// Poly1305::update
// ============================================================================

#[test]
fn test_what_update_wrote_is_found_while_the_state_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&ACC))?;

    let mut key = a_key();

    forensics!({
        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let poly = Box::leak(Box::new(Poly1305::new()));

        poly.init(Backend::default(), &key);
        key.fast_zeroize();

        capture(|| poly.update(Backend::default(), MESSAGE));
    });

    is_found(&watch.snapshot()?, "a state updated, and kept");

    Ok(())
}

#[test]
fn test_update_leaves_nothing() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[("key", &KEY), ("r", &R), ("accumulator", &ACC)])?;

    let mut key = a_key();
    let mut poly = Poly1305::new();

    poly.init(Backend::default(), &key);
    key.fast_zeroize();

    forensics!({
        capture(|| poly.update(Backend::default(), MESSAGE));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The state is the caller's.
        poly.fast_zeroize();
    });

    watching.none_left("update")?;

    Ok(())
}

// ============================================================================
// Poly1305::update_padded
// ============================================================================

#[test]
fn test_what_update_padded_wrote_is_found_while_the_state_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&ACC_PADDED))?;

    let mut key = a_key();

    forensics!({
        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let poly = Box::leak(Box::new(Poly1305::new()));

        poly.init(Backend::default(), &key);
        key.fast_zeroize();

        capture(|| poly.update_padded(Backend::default(), MESSAGE));
    });

    is_found(&watch.snapshot()?, "a state updated with padding, and kept");

    Ok(())
}

#[test]
fn test_update_padded_leaves_nothing() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[
        ("key", &KEY),
        ("r", &R),
        ("accumulator", &ACC),
        ("padded accumulator", &ACC_PADDED),
    ])?;

    let mut key = a_key();
    let mut poly = Poly1305::new();

    poly.init(Backend::default(), &key);
    key.fast_zeroize();

    forensics!({
        capture(|| poly.update_padded(Backend::default(), MESSAGE));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The state is the caller's.
        poly.fast_zeroize();
    });

    watching.none_left("update_padded")?;

    Ok(())
}

// ============================================================================
// Poly1305::finalize_mut
// ============================================================================

#[test]
fn test_what_finalize_wrote_is_found_while_the_caller_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&TAG))?;

    let mut key = a_key();
    let mut poly = Poly1305::new();

    poly.init(Backend::default(), &key);
    poly.update(Backend::default(), MESSAGE);
    key.fast_zeroize();

    forensics!({
        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let out = Box::leak(Box::new([0_u8; TAG_SIZE]));

        capture(|| poly.finalize_mut(Backend::default(), out));
    });

    is_found(&watch.snapshot()?, "a tag finalized, and kept");

    Ok(())
}

#[test]
fn test_finalize_leaves_nothing() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[
        ("key", &KEY),
        ("r", &R),
        ("accumulator", &ACC),
        ("tag", &TAG),
    ])?;

    let mut key = a_key();
    let mut poly = Poly1305::new();

    poly.init(Backend::default(), &key);
    poly.update(Backend::default(), MESSAGE);
    key.fast_zeroize();

    forensics!({
        let mut out = [0_u8; TAG_SIZE];

        capture(|| poly.finalize_mut(Backend::default(), &mut out));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The state is not emptied here: that is finalize's to do, and its
        // drop runs only once the photograph is taken.
        out.fast_zeroize();
    });

    watching.none_left("finalize")?;

    Ok(())
}

// ============================================================================
// Poly1305, dropped
// ============================================================================

/// A drop takes the state by value, and a value moved is a copy: the drop
/// empties the one it was handed, and the slot it was moved out of keeps
/// everything.
#[test]
fn test_what_a_state_dropped_by_value_held_is_found_where_it_was() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&R))?;

    let mut key = a_key();
    let mut poly = Poly1305::new();

    poly.init(Backend::default(), &key);
    poly.update(Backend::default(), MESSAGE);
    key.fast_zeroize();

    forensics!({
        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(poly));
    });

    is_found(&watch.snapshot()?, "a state dropped by value");

    Ok(())
}

/// What a caller that lets go of one by hand owes it: emptied in place first,
/// so what the move copies is nothing.
#[test]
fn test_a_state_zeroized_and_then_dropped_leaves_nothing() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[("key", &KEY), ("r", &R), ("accumulator", &ACC)])?;

    let mut key = a_key();
    let mut poly = Poly1305::new();

    poly.init(Backend::default(), &key);
    poly.update(Backend::default(), MESSAGE);
    key.fast_zeroize();

    forensics!({
        poly.fast_zeroize();

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| drop(poly));
    });

    watching.none_left("a state zeroized and then dropped")?;

    Ok(())
}

// ============================================================================
// tag
// ============================================================================

#[test]
fn test_what_tag_wrote_is_found_while_the_caller_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards(&TAG))?;

    let mut key = a_key();

    forensics!({
        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let out = Box::leak(Box::new([0_u8; TAG_SIZE]));

        capture(|| tag(Backend::default(), &key, MESSAGE, out));

        key.fast_zeroize();
    });

    is_found(&watch.snapshot()?, "a tag, and kept");

    Ok(())
}

#[test]
fn test_tag_leaves_nothing() -> Result<(), AnyError> {
    let mut watching = Watching::start(&[
        ("key", &KEY),
        ("r", &R),
        ("accumulator", &ACC),
        ("tag", &TAG),
    ])?;

    let mut key = a_key();

    forensics!({
        let mut out = [0_u8; TAG_SIZE];

        capture(|| tag(Backend::default(), &key, MESSAGE, &mut out));

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The key and the tag are the caller's.
        key.fast_zeroize();
        out.fast_zeroize();
    });

    watching.none_left("tag")?;

    Ok(())
}
