// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each routine leaves behind, asked of the two verifiers in `probes`.
//!
//! Those two are swept there — every register one at a time, every byte of the
//! frame one at a time — so here they are used and not measured. What is
//! measured here is the routine, and only what it left: whether it computes the
//! right tag is settled in `poly1305.rs`, where both backends run the vectors
//! and the oracle. An assertion about an answer would make every test below
//! two tests.
//!
//! Three per routine, the two negatives first and the real one last, because
//! the negatives are what make it mean anything.
//!
//! The real one is four calls with nothing between them. The dirtying goes
//! first, because a machine that reads empty afterwards would otherwise say
//! only that nobody wrote it. The registers are asked before the frame,
//! because reading a hundred and sixty bytes takes registers.
//!
//! These are not claims about kernel signal frames, swap, dumps, or the input
//! and output the caller owns.

mod probes;

use std::vec::Vec;

use redoubt_aead_v2_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

use crate::consts::LIMBS;

// The assembly, in the order the file declares it: the three entry points the
// backend calls, then the probe, which nothing in production calls.
unsafe extern "C" {
    fn redoubt_poly1305_init(r: *mut u32, s: *mut u8, key: *const u8);
    fn redoubt_poly1305_update(
        acc: *mut u64,
        r: *const u32,
        block: *mut u8,
        filled: *mut usize,
        said: *const u8,
        said_len: usize,
    );
    fn redoubt_poly1305_finalize(
        acc: *mut u64,
        r: *const u32,
        s: *const u8,
        said: *const u8,
        said_len: usize,
        out: *mut u8,
    );

    // The probe, last and apart: what asks first, then what is asked about.
    fn redoubt_poly1305_registers_are_zeroized() -> u64;
    fn redoubt_poly1305_frame_is_zeroized() -> u64;
    fn redoubt_poly1305_dirty_registers();
    fn redoubt_poly1305_dirty_frame(at: usize);
    fn redoubt_poly1305_clean_frame();
}

/// The clamped key the two routines after `init` are given.
///
/// It comes from `init` itself rather than from the other backend: what these
/// routines leave behind does not depend on the value being right, and asking
/// the Rust side for it would put a second implementation in a file that is
/// measuring one.
fn clamped() -> ([u32; LIMBS], [u8; BLOCK_SIZE]) {
    let key: [u8; KEY_SIZE] = core::array::from_fn(|at| 0x40 + at as u8);
    let mut r = [0u32; LIMBS];
    let mut s = [0u8; BLOCK_SIZE];

    // SAFETY: the three arrays are disjoint and have the widths the routine
    // reads and writes.
    unsafe { redoubt_poly1305_init(r.as_mut_ptr(), s.as_mut_ptr(), key.as_ptr()) };

    (r, s)
}

/// The two negatives every routine below is given, one routine at a time.
///
/// They are what make the third test mean anything, and they are written per
/// routine rather than once because what they measure is per routine: between
/// the dirtying and the verifier the compiler emits the call sequence for
/// *that* routine, and the sequence for three arguments is not the sequence
/// for six. Nothing in the language promises either of them emits nothing
/// else. If one put an instruction there that dirtied a register or moved the
/// stack pointer, the pair fails — which makes it a measurement of what this
/// compiler did rather than an argument about what compilers do.
///
/// One byte is enough for the frame: the sweep in `asm.rs` has already
/// established that any of the hundred and sixty is seen.
macro_rules! test_the_calls_carry_what_was_left {
    ($registers:ident, $frame:ident) => {
        #[test]
        fn $registers() {
            // SAFETY: the target takes no argument and leaves the budget full.
            let registers = unsafe {
                redoubt_poly1305_dirty_registers();
                redoubt_poly1305_registers_are_zeroized()
            };

            assert_ne!(registers, 0, "a register nothing cleared reads as cleared");
        }

        #[test]
        fn $frame() {
            // SAFETY: the target writes one byte inside the frame it allocated.
            let frame = unsafe {
                redoubt_poly1305_dirty_frame(0);
                redoubt_poly1305_frame_is_zeroized()
            };

            assert_ne!(frame, 0, "a frame nothing cleared reads as cleared");
        }
    };
}

// === === === === === === === === === ===
// init
// === === === === === === === === === ===

test_the_calls_carry_what_was_left!(
    test_a_register_left_full_is_seen_across_the_init_calls,
    test_a_frame_left_full_is_seen_across_the_init_calls
);

#[test]
fn test_init_leaves_nothing_in_the_registers_and_takes_no_frame() {
    let key: [u8; KEY_SIZE] = core::array::from_fn(|at| 0x40 + at as u8);
    let mut r = [0u32; LIMBS];
    let mut s = [0u8; BLOCK_SIZE];

    // SAFETY: the three arrays are disjoint and have the widths the routine
    // reads and writes.
    let (registers, frame) = unsafe {
        redoubt_poly1305_dirty_registers();
        redoubt_poly1305_dirty_frame(0);
        redoubt_poly1305_init(r.as_mut_ptr(), s.as_mut_ptr(), key.as_ptr());
        (
            redoubt_poly1305_registers_are_zeroized(),
            redoubt_poly1305_frame_is_zeroized(),
        )
    };

    // Assert zeroization!
    assert_eq!(registers, 0, "the registers after the clamp");

    // The clamp fits in the budget, so this routine allocates nothing and the
    // byte left under it has to still be there. An emptied window here would
    // mean it reached for memory its layout never declared.
    assert_ne!(frame, 0, "a routine that takes no frame emptied one");
}

// === === === === === === === === === ===
// update
// === === === === === === === === === ===

test_the_calls_carry_what_was_left!(
    test_a_register_left_full_is_seen_across_the_update_calls,
    test_a_frame_left_full_is_seen_across_the_update_calls
);

#[test]
fn test_update_leaves_nothing_in_the_registers_or_the_frame() {
    let (r, _) = clamped();

    // Every way the buffer can be on the way in, against every way the next
    // piece of message can leave it: short of a block, exactly one, and past
    // it with a tail.
    for filled in [0, 1, 8, 15] {
        for length in [0, 1, 15, 16, 17, 31, 32, 64, 65] {
            let said: Vec<u8> = (0..length).map(|at| (at as u8) ^ 0x5a).collect();

            let mut acc = [0u64; LIMBS];
            let mut block = [0u8; BLOCK_SIZE];
            let mut held = filled;
            block[..filled].fill(0xc3);

            // SAFETY: every pointer is to storage of the width the routine
            // reads or writes, `said` is as long as the length beside it, and
            // `filled` is no greater than the block it indexes.
            let (registers, frame) = unsafe {
                redoubt_poly1305_dirty_registers();
                redoubt_poly1305_dirty_frame(0);
                redoubt_poly1305_update(
                    acc.as_mut_ptr(),
                    r.as_ptr(),
                    block.as_mut_ptr(),
                    &raw mut held,
                    said.as_ptr(),
                    length,
                );
                (
                    redoubt_poly1305_registers_are_zeroized(),
                    redoubt_poly1305_frame_is_zeroized(),
                )
            };

            // Assert zeroization!
            assert_eq!(registers, 0, "the registers, {filled} held, {length} in");
            assert_eq!(frame, 0, "the frame, {filled} held, {length} in");
        }
    }
}

// === === === === === === === === === ===
// finalize
// === === === === === === === === === ===

test_the_calls_carry_what_was_left!(
    test_a_register_left_full_is_seen_across_the_finalize_calls,
    test_a_frame_left_full_is_seen_across_the_finalize_calls
);

#[test]
fn test_finalize_leaves_nothing_in_the_registers_or_the_frame() {
    let (r, s) = clamped();

    // Every tail a message can end on, and one that spans several blocks.
    for length in [0, 1, 2, 15, 16, 17, 31, 32, 33, 64, 65] {
        let said: Vec<u8> = (0..length).map(|at| (at as u8) ^ 0x5a).collect();
        let mut acc = [0u64; LIMBS];
        let mut tag = [0u8; TAG_SIZE];

        // SAFETY: every pointer is to an array of the width the routine reads
        // or writes, and `said` is as long as the length beside it.
        let (registers, frame) = unsafe {
            redoubt_poly1305_dirty_registers();
            redoubt_poly1305_dirty_frame(0);
            redoubt_poly1305_finalize(
                acc.as_mut_ptr(),
                r.as_ptr(),
                s.as_ptr(),
                said.as_ptr(),
                length,
                tag.as_mut_ptr(),
            );
            (
                redoubt_poly1305_registers_are_zeroized(),
                redoubt_poly1305_frame_is_zeroized(),
            )
        };

        // Assert zeroization!
        assert_eq!(registers, 0, "the registers after {length} bytes in");
        assert_eq!(frame, 0, "the frame after {length} bytes in");
    }
}
