// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Observe the machine immediately after the assembly returns, before Rust
//! can reuse its registers or stack. These tests are not claims about kernel
//! signal frames, swap, dumps, or caller-owned input and output.

use std::vec::Vec;

use redoubt_aead_v2_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

use crate::consts::LIMBS;

unsafe extern "C" {
    fn redoubt_poly1305_probe(call: *const usize, snapshot: *mut u64);
    fn redoubt_poly1305_untouched();
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
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    include_str!("support/probe_x86_64.S"),
    probe = sym redoubt_poly1305_probe,
    untouched = sym redoubt_poly1305_untouched,
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    include_str!("support/probe_aarch64.S"),
    probe = sym redoubt_poly1305_probe,
    untouched = sym redoubt_poly1305_untouched,
);

#[cfg(target_arch = "x86_64")]
const CALLER_WORDS: usize = 9;
#[cfg(target_arch = "aarch64")]
const CALLER_WORDS: usize = 18;
#[cfg(target_arch = "x86_64")]
const PRESERVED_WORDS: usize = 6;
#[cfg(target_arch = "aarch64")]
const PRESERVED_WORDS: usize = 11;
#[cfg(target_arch = "x86_64")]
const GUARD_AT: usize = 15;
#[cfg(target_arch = "aarch64")]
const GUARD_AT: usize = 31;
#[cfg(target_arch = "x86_64")]
const FRAME_AT: usize = 18;
#[cfg(target_arch = "aarch64")]
const FRAME_AT: usize = 35;
#[cfg(target_arch = "x86_64")]
const SNAPSHOT_WORDS: usize = 38;
#[cfg(target_arch = "aarch64")]
const SNAPSHOT_WORDS: usize = 55;

const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

// === === === === === === === === === ===
// Test helpers
// === === === === === === === === === ===

/// Call an assembly entry point and inspect its registers and released frame.
///
/// `allocated_frame` says whether the routine took a frame at all. One that
/// took none has to leave the poison where it was: an emptied window under a
/// routine that never reached for it would mean the probe is wiping its own
/// measurement.
///
/// SAFETY: call[0] must name one of the declared entry points and call[1..]
/// must satisfy that function's pointer and length preconditions.
unsafe fn observe(call: [usize; 7], allocated_frame: bool) {
    let mut snapshot = [u64::MAX; SNAPSHOT_WORDS];

    // SAFETY: the caller supplies valid arguments. The probe reads exactly
    // seven words and writes the architecture's documented snapshot size.
    unsafe { redoubt_poly1305_probe(call.as_ptr(), snapshot.as_mut_ptr()) };

    assert_eq!(
        &snapshot[..CALLER_WORDS],
        &[0; CALLER_WORDS],
        "caller-saved registers"
    );

    for (at, &value) in snapshot[CALLER_WORDS..CALLER_WORDS + PRESERVED_WORDS]
        .iter()
        .enumerate()
    {
        assert_eq!(value, 19 + at as u64, "callee-saved register {at}");
    }

    #[cfg(target_arch = "aarch64")]
    assert_eq!(snapshot[29], snapshot[30], "platform register x18");

    assert!(
        snapshot[GUARD_AT..FRAME_AT]
            .iter()
            .all(|&word| word == POISON),
        "frame underrun"
    );

    let expected = if allocated_frame { 0 } else { POISON };
    assert!(
        snapshot[FRAME_AT..].iter().all(|&word| word == expected),
        "released stack frame: {:?}",
        &snapshot[FRAME_AT..]
    );
}

// === === === === === === === === === ===
// redoubt_poly1305_probe
// === === === === === === === === === ===

#[test]
fn test_probe_reports_the_registers_a_call_left_alone() {
    let mut snapshot = [0u64; SNAPSHOT_WORDS];

    // SAFETY: the target takes no arguments and returns at once, so every
    // slot below is a value it never reads.
    unsafe {
        redoubt_poly1305_probe(
            [
                redoubt_poly1305_untouched as *const () as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
            ]
            .as_ptr(),
            snapshot.as_mut_ptr(),
        );
    }

    // What every other test here asserts is that a register came back empty.
    // That is worth nothing unless an empty one can be told from a full one,
    // and this is where that is established: nothing cleared these, so none of
    // them may read as cleared.
    assert!(
        snapshot[..CALLER_WORDS].iter().all(|&word| word != 0),
        "a register nothing touched reads as empty: {:?}",
        &snapshot[..CALLER_WORDS]
    );

    assert!(
        snapshot[GUARD_AT..].iter().all(|&word| word == POISON),
        "a frame nothing touched reads as emptied"
    );
}

// === === === === === === === === === ===
// init
// === === === === === === === === === ===

#[test]
fn test_init_zeroizes_its_registers() {
    let key: [u8; KEY_SIZE] = core::array::from_fn(|at| 0x40 + at as u8);
    let mut r = [0u32; LIMBS];
    let mut s = [0u8; BLOCK_SIZE];

    // SAFETY: the three arrays are disjoint and have the widths the routine
    // reads and writes. The trailing slots are values it never reads.
    unsafe {
        observe(
            [
                redoubt_poly1305_init as *const () as usize,
                r.as_mut_ptr() as usize,
                s.as_mut_ptr() as usize,
                key.as_ptr() as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
            ],
            false,
        );
    }

    let mut expected_r = [0u32; LIMBS];
    let mut expected_s = [0u8; BLOCK_SIZE];
    crate::backend::rust::init(&mut expected_r, &mut expected_s, &key);

    assert_eq!(r, expected_r);
    assert_eq!(s, expected_s);
}

// === === === === === === === === === ===
// update
// === === === === === === === === === ===

#[test]
fn test_update_zeroizes_its_registers_and_frame() {
    let key: [u8; KEY_SIZE] = core::array::from_fn(|at| 0x40 + at as u8);
    let mut r = [0u32; LIMBS];
    let mut s = [0u8; BLOCK_SIZE];
    crate::backend::rust::init(&mut r, &mut s, &key);

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

            let mut expected_acc = [0u64; LIMBS];
            let mut expected_block = block;
            let mut expected_held = filled;

            // SAFETY: every pointer is to storage of the width the routine
            // reads or writes, `said` is as long as the length beside it, and
            // `filled` is no greater than the block it indexes.
            unsafe {
                observe(
                    [
                        redoubt_poly1305_update as *const () as usize,
                        acc.as_mut_ptr() as usize,
                        r.as_ptr() as usize,
                        block.as_mut_ptr() as usize,
                        &raw mut held as usize,
                        said.as_ptr() as usize,
                        length,
                    ],
                    true,
                );
            }

            crate::backend::rust::update(
                &mut expected_acc,
                &r,
                &mut expected_block,
                &mut expected_held,
                &said,
            );

            assert_eq!(acc, expected_acc, "{filled} held, {length} bytes in");
            assert_eq!(block, expected_block, "{filled} held, {length} bytes in");
            assert_eq!(held, expected_held, "{filled} held, {length} bytes in");
        }
    }
}

// === === === === === === === === === ===
// finalize
// === === === === === === === === === ===

#[test]
fn test_finalize_zeroizes_its_registers_and_frame() {
    let key: [u8; KEY_SIZE] = core::array::from_fn(|at| 0x40 + at as u8);
    let mut r = [0u32; LIMBS];
    let mut s = [0u8; BLOCK_SIZE];
    crate::backend::rust::init(&mut r, &mut s, &key);

    // Every tail a message can end on, and one that spans several blocks.
    for length in [0, 1, 2, 15, 16, 17, 31, 32, 33, 64, 65] {
        let said: Vec<u8> = (0..length).map(|at| (at as u8) ^ 0x5a).collect();
        let mut acc = [0u64; LIMBS];
        let mut tag = [0u8; TAG_SIZE];

        // SAFETY: every pointer is to an array of the width the routine reads
        // or writes, and `said` is as long as the length beside it.
        unsafe {
            observe(
                [
                    redoubt_poly1305_finalize as *const () as usize,
                    acc.as_mut_ptr() as usize,
                    r.as_ptr() as usize,
                    s.as_ptr() as usize,
                    said.as_ptr() as usize,
                    length,
                    tag.as_mut_ptr() as usize,
                ],
                true,
            );
        }

        let mut expected_acc = [0u64; LIMBS];
        let mut expected_tag = [0u8; TAG_SIZE];
        crate::backend::rust::finalize(&mut expected_acc, &r, &s, &said, &mut expected_tag);

        assert_eq!(tag, expected_tag, "{length} bytes in");
        assert_eq!(acc, expected_acc, "{length} bytes in");
    }
}
