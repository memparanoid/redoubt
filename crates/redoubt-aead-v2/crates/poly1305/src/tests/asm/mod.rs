// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each routine leaves behind, asked of the two verifiers in `probes`.
//!
//! Their own tests live there; here they are used and not measured. What is
//! measured here is the routine, and only what it left: whether it computes the
//! right tag is settled in `poly1305.rs`, where both backends run the vectors
//! and the oracle. An assertion about an answer would make every test below
//! two tests.
//!
//! Four cases per routine, the three negatives first and the real one last,
//! because the negatives are what make it mean anything. Two of them leave a
//! residue of their own; the third leaves the machine exactly as it arrived,
//! which is what says the reading is about the routine and not about the call
//! site having tidied up.
//!
//! The dirtying goes first. The selected routine and both verifiers then run
//! in one assembly block, so Rust cannot insert work before the measurement.
//! The register verdict is kept in a callee-saved register while the frame is
//! scanned; that move neither changes the stack pointer nor touches the frame.
//!
//! These are not claims about kernel signal frames, swap, dumps, or the input
//! and output the caller owns.

mod probes;

use std::vec::Vec;

use rstest::rstest;

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

/// Three stand-ins for the routine, with its arguments and none of its work.
///
/// The tail branch keeps the caller's stack pointer and return address. A
/// regular Rust wrapper could take another frame or change the registers on
/// return, making the residue belong to the wrapper instead of the helper.
///
/// The first two leave a residue of their own, which is what says the verifier
/// sees one across this call site. The third leaves none and does nothing at
/// all: it is the only one that measures the gap, because the other two dirty
/// the machine again from inside the call. What it answers is whether the
/// *caller's* dirtying survives to the verifier — without it, the real routine
/// reading clean could be the call site having cleaned rather than the routine.
///
/// Only the frame stand-in replaces the first argument with byte offset zero.
/// These functions never dereference their pointer arguments.
macro_rules! controls {
    ($registers:ident, $frame:ident, $untouched:ident, ($($argument:ident: $kind:ty),* $(,)?)) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $untouched($($argument: $kind),*) {
            core::arch::naked_asm!("ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $registers($($argument: $kind),*) {
            #[cfg(target_arch = "x86_64")]
            core::arch::naked_asm!(
                "jmp {target}",
                target = sym redoubt_poly1305_dirty_registers,
            );

            #[cfg(target_arch = "aarch64")]
            core::arch::naked_asm!(
                "b {target}",
                target = sym redoubt_poly1305_dirty_registers,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $frame($($argument: $kind),*) {
            #[cfg(target_arch = "x86_64")]
            core::arch::naked_asm!(
                "xor edi, edi",
                "jmp {target}",
                target = sym redoubt_poly1305_dirty_frame,
            );

            #[cfg(target_arch = "aarch64")]
            core::arch::naked_asm!(
                "mov x0, xzr",
                "b {target}",
                target = sym redoubt_poly1305_dirty_frame,
            );
        }
    };
}

/// Call the selected routine with its ABI arguments and immediately measure it.
///
/// The caller must uphold the routine's pointer and length preconditions.
/// Both verifiers preserve r12/x20, where the first verdict waits for the
/// second. Declaring that output makes Rust preserve its caller's value.
macro_rules! measure {
    ($routine:expr, $first:expr $(, ($x86:tt, $arm:tt, $argument:expr))* $(,)?) => {{
        let registers: u64;
        let frame: u64;

        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "call r11",
            "call {register_probe}",
            "mov r12, rax",
            "call {frame_probe}",
            register_probe = sym redoubt_poly1305_registers_are_zeroized,
            frame_probe = sym redoubt_poly1305_frame_is_zeroized,
            inlateout("r11") $routine => _,
            inlateout("rdi") $first => _,
            $(inlateout($x86) $argument => _,)*
            lateout("r12") registers,
            lateout("rax") frame,
            clobber_abi("C"),
        );

        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "blr x16",
            "bl {register_probe}",
            "mov x20, x0",
            "bl {frame_probe}",
            register_probe = sym redoubt_poly1305_registers_are_zeroized,
            frame_probe = sym redoubt_poly1305_frame_is_zeroized,
            inlateout("x16") $routine => _,
            inlateout("x0") $first => frame,
            $(inlateout($arm) $argument => _,)*
            lateout("x20") registers,
            clobber_abi("C"),
        );

        (registers, frame)
    }};
}

/// Which residue the case deliberately leaves, or neither for the real call.
#[derive(Clone, Copy)]
enum Left {
    Registers,
    Frame,
    Everything,
    Nothing,
}

/// Each negative asks only about the residue it deliberately leaves.
fn assert_residue(registers: u64, frame: u64, left: Left, takes_frame: bool) {
    match left {
        Left::Everything => {
            // A call that did nothing at all. What the caller dirtied before it
            // has to still be there afterwards, or a clean reading below says
            // only that something between the calls tidied up.
            assert_ne!(
                registers, 0,
                "a call that ran nothing emptied the registers"
            );
            assert_ne!(frame, 0, "a call that ran nothing emptied the frame");
        }
        Left::Registers => {
            assert_ne!(
                registers, 0,
                "registers the replacement left full read as empty"
            );
        }
        Left::Frame => {
            assert_ne!(
                frame, 0,
                "the frame the replacement left full reads as empty"
            );
        }
        Left::Nothing => {
            // Assert zeroization!
            assert_eq!(registers, 0, "the registers after the real routine");

            if takes_frame {
                assert_eq!(frame, 0, "the frame after the real routine");
            } else {
                assert_ne!(frame, 0, "a routine that takes no frame emptied one");
            }
        }
    }
}

// === === === === === === === === === ===
// init
// === === === === === === === === === ===

type Init = unsafe extern "C" fn(*mut u32, *mut u8, *const u8);

controls!(
    dirty_init_registers,
    dirty_init_frame,
    untouched_init,
    (_r: *mut u32, _s: *mut u8, _key: *const u8)
);

#[rstest]
#[case::registers_left_full(dirty_init_registers as Init, Left::Registers)]
#[case::frame_left_full(dirty_init_frame as Init, Left::Frame)]
#[case::nothing_ran(untouched_init as Init, Left::Everything)]
#[case::real(redoubt_poly1305_init as Init, Left::Nothing)]
fn test_init_leaves_the_residue_its_case_declares(#[case] routine: Init, #[case] left: Left) {
    // All cases use this indirect call site, including under release/LTO.
    // The controls exercise this caller; they do not certify other callers.
    let routine = core::hint::black_box(routine);
    let key: [u8; KEY_SIZE] = core::array::from_fn(|at| 0x40 + at as u8);
    let mut r = [0u32; LIMBS];
    let mut s = [0u8; BLOCK_SIZE];

    // SAFETY: the three arrays are disjoint and have the widths the routine
    // reads and writes.
    let (registers, frame) = unsafe {
        redoubt_poly1305_dirty_registers();
        redoubt_poly1305_dirty_frame(0);
        measure!(
            routine,
            r.as_mut_ptr(),
            ("rsi", "x1", s.as_mut_ptr()),
            ("rdx", "x2", key.as_ptr()),
        )
    };

    // The real clamp takes no frame; its pre-dirtied byte must remain.
    assert_residue(registers, frame, left, false);
}

// === === === === === === === === === ===
// update
// === === === === === === === === === ===

type Update = unsafe extern "C" fn(*mut u64, *const u32, *mut u8, *mut usize, *const u8, usize);

controls!(
    dirty_update_registers,
    dirty_update_frame,
    untouched_update,
    (
        _acc: *mut u64, _r: *const u32, _block: *mut u8,
        _filled: *mut usize, _said: *const u8, _said_len: usize,
    )
);

#[rstest]
#[case::registers_left_full(dirty_update_registers as Update, Left::Registers)]
#[case::frame_left_full(dirty_update_frame as Update, Left::Frame)]
#[case::nothing_ran(untouched_update as Update, Left::Everything)]
#[case::real(redoubt_poly1305_update as Update, Left::Nothing)]
fn test_update_leaves_the_residue_its_case_declares(#[case] routine: Update, #[case] left: Left) {
    let routine = core::hint::black_box(routine);
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
                measure!(
                    routine,
                    acc.as_mut_ptr(),
                    ("rsi", "x1", r.as_ptr()),
                    ("rdx", "x2", block.as_mut_ptr()),
                    ("rcx", "x3", &raw mut held),
                    ("r8", "x4", said.as_ptr()),
                    ("r9", "x5", length),
                )
            };

            assert_residue(registers, frame, left, true);
        }
    }
}

// === === === === === === === === === ===
// finalize
// === === === === === === === === === ===

type Finalize = unsafe extern "C" fn(*mut u64, *const u32, *const u8, *const u8, usize, *mut u8);

controls!(
    dirty_finalize_registers,
    dirty_finalize_frame,
    untouched_finalize,
    (
        _acc: *mut u64, _r: *const u32, _s: *const u8,
        _said: *const u8, _said_len: usize, _out: *mut u8,
    )
);

#[rstest]
#[case::registers_left_full(dirty_finalize_registers as Finalize, Left::Registers)]
#[case::frame_left_full(dirty_finalize_frame as Finalize, Left::Frame)]
#[case::nothing_ran(untouched_finalize as Finalize, Left::Everything)]
#[case::real(redoubt_poly1305_finalize as Finalize, Left::Nothing)]
fn test_finalize_leaves_the_residue_its_case_declares(
    #[case] routine: Finalize,
    #[case] left: Left,
) {
    let routine = core::hint::black_box(routine);
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
            measure!(
                routine,
                acc.as_mut_ptr(),
                ("rsi", "x1", r.as_ptr()),
                ("rdx", "x2", s.as_ptr()),
                ("rcx", "x3", said.as_ptr()),
                ("r8", "x4", length),
                ("r9", "x5", tag.as_mut_ptr()),
            )
        };

        assert_residue(registers, frame, left, true);
    }
}
