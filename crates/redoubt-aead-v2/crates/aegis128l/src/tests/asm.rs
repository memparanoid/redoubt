// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each routine leaves behind, asked of the two verifiers in `probes`.
//!
//! Their own tests live there; here they are used and not measured. What is
//! measured here is the routine, and only what it left: whether it computes the
//! right tag is settled against the published vectors, where an answer can be
//! compared to one somebody else published. An assertion about an answer would
//! make every test below two tests.
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
//! Whether a routine takes a frame at all is decided by its arguments and not
//! by the target: the stack is reached for a tail that does not fill a block,
//! so an AAD and a message that are both whole numbers of blocks never touch
//! it. Both halves are swept below, and the one that takes none asserts the
//! poison survives.
//!
//! These are not claims about kernel signal frames, swap, dumps, or the input
//! and output the caller owns.

use std::vec::Vec;

use rstest::rstest;

use redoubt_aead_v2_core::consts::aegis::{BLOCK_SIZE, TAG_SIZE};

use super::{
    material, redoubt_aegis128l_decrypt, redoubt_aegis128l_dirty_frame,
    redoubt_aegis128l_dirty_registers, redoubt_aegis128l_encrypt,
    redoubt_aegis128l_frame_is_zeroized, redoubt_aegis128l_registers_are_zeroized,
};

/// What both routines take, in the order they take it.
type Routine =
    unsafe extern "C" fn(*const u8, *const u8, *const u8, usize, *mut u8, usize, *mut u8);

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
    ($registers:ident, $frame:ident, $untouched:ident) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $untouched(
            _key: *const u8,
            _nonce: *const u8,
            _aad: *const u8,
            _aad_len: usize,
            _data: *mut u8,
            _data_len: usize,
            _tag: *mut u8,
        ) {
            core::arch::naked_asm!("ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $registers(
            _key: *const u8,
            _nonce: *const u8,
            _aad: *const u8,
            _aad_len: usize,
            _data: *mut u8,
            _data_len: usize,
            _tag: *mut u8,
        ) {
            #[cfg(target_arch = "x86_64")]
            core::arch::naked_asm!(
                "jmp {target}",
                target = sym redoubt_aegis128l_dirty_registers,
            );

            #[cfg(target_arch = "aarch64")]
            core::arch::naked_asm!(
                "b {target}",
                target = sym redoubt_aegis128l_dirty_registers,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $frame(
            _key: *const u8,
            _nonce: *const u8,
            _aad: *const u8,
            _aad_len: usize,
            _data: *mut u8,
            _data_len: usize,
            _tag: *mut u8,
        ) {
            #[cfg(target_arch = "x86_64")]
            core::arch::naked_asm!(
                "xor edi, edi",
                "jmp {target}",
                target = sym redoubt_aegis128l_dirty_frame,
            );

            #[cfg(target_arch = "aarch64")]
            core::arch::naked_asm!(
                "mov x0, xzr",
                "b {target}",
                target = sym redoubt_aegis128l_dirty_frame,
            );
        }
    };
}

/// Call the selected routine with its ABI arguments and immediately measure it.
///
/// The caller must uphold the routine's pointer and length preconditions.
/// Both verifiers preserve r12/x20, where the first verdict waits for the
/// second. Declaring that output makes Rust preserve its caller's value.
///
/// Seven arguments is one more than SysV passes in registers, so on x86-64 the
/// last goes on the stack and the stack pointer stays where it was put until
/// both verifiers have run. Giving those sixteen bytes back any earlier would
/// have the second verifier read sixteen bytes above the frame the routine
/// used. AArch64 passes all seven in registers.
macro_rules! measure {
    ($routine:expr, $key:expr, $nonce:expr, $aad:expr, $aad_len:expr,
     $data:expr, $data_len:expr, $tag:expr $(,)?) => {{
        let registers: u64;
        let frame: u64;

        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "sub rsp, 16",
            "mov [rsp], r10",
            "call r11",
            "call {register_probe}",
            "mov r12, rax",
            "call {frame_probe}",
            "add rsp, 16",
            register_probe = sym redoubt_aegis128l_registers_are_zeroized,
            frame_probe = sym redoubt_aegis128l_frame_is_zeroized,
            inlateout("r11") $routine => _,
            inlateout("rdi") $key => _,
            inlateout("rsi") $nonce => _,
            inlateout("rdx") $aad => _,
            inlateout("rcx") $aad_len => _,
            inlateout("r8") $data => _,
            inlateout("r9") $data_len => _,
            inlateout("r10") $tag => _,
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
            register_probe = sym redoubt_aegis128l_registers_are_zeroized,
            frame_probe = sym redoubt_aegis128l_frame_is_zeroized,
            inlateout("x16") $routine => _,
            inlateout("x0") $key => frame,
            inlateout("x1") $nonce => _,
            inlateout("x2") $aad => _,
            inlateout("x3") $aad_len => _,
            inlateout("x4") $data => _,
            inlateout("x5") $data_len => _,
            inlateout("x6") $tag => _,
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

/// Whether these two lengths make a routine reach for its frame.
///
/// Zero counts as a whole number of blocks and takes none.
fn takes_a_frame(aad_len: usize, data_len: usize) -> bool {
    !aad_len.is_multiple_of(BLOCK_SIZE) || !data_len.is_multiple_of(BLOCK_SIZE)
}

/// Every way an AAD can sit against a block boundary, and one that spans
/// several.
const AAD_LENGTHS: [usize; 6] = [0, 1, 31, 32, 33, 64];

/// Every way a message can sit against a block boundary, both sides of each.
const DATA_LENGTHS: [usize; 9] = [0, 1, 15, 16, 17, 31, 32, 33, 65];

/// A buffer of `length` bytes, none of them zero.
///
/// None of them zero on purpose: a tail of zeros copied into the frame would
/// leave it reading as though it had already been emptied.
fn said(length: usize) -> Vec<u8> {
    (0..length).map(|at| ((at as u8) ^ 0x5a) | 1).collect()
}

// === === === === === === === === === ===
// encrypt
// === === === === === === === === === ===

controls!(
    dirty_encrypt_registers,
    dirty_encrypt_frame,
    untouched_encrypt
);

#[rstest]
#[case::registers_left_full(dirty_encrypt_registers as Routine, Left::Registers)]
#[case::frame_left_full(dirty_encrypt_frame as Routine, Left::Frame)]
#[case::nothing_ran(untouched_encrypt as Routine, Left::Everything)]
#[case::real(redoubt_aegis128l_encrypt as Routine, Left::Nothing)]
fn test_encrypt_leaves_the_residue_its_case_declares(#[case] routine: Routine, #[case] left: Left) {
    // All cases use this indirect call site, including under release/LTO.
    // The controls exercise this caller; they do not certify other callers.
    let routine = core::hint::black_box(routine);
    let (key, nonce) = material();

    for aad_len in AAD_LENGTHS {
        for data_len in DATA_LENGTHS {
            let aad = said(aad_len);
            let mut data = said(data_len);
            let mut tag = [0u8; TAG_SIZE];

            // SAFETY: every pointer is to storage of the width the routine
            // reads or writes, and the buffers are distinct allocations.
            let (registers, frame) = unsafe {
                redoubt_aegis128l_dirty_registers();
                redoubt_aegis128l_dirty_frame(0);
                measure!(
                    routine,
                    key.as_ptr(),
                    nonce.as_ptr(),
                    aad.as_ptr(),
                    aad_len,
                    data.as_mut_ptr(),
                    data_len,
                    tag.as_mut_ptr(),
                )
            };

            assert_residue(registers, frame, left, takes_a_frame(aad_len, data_len));
        }
    }
}

// === === === === === === === === === ===
// decrypt
// === === === === === === === === === ===

controls!(
    dirty_decrypt_registers,
    dirty_decrypt_frame,
    untouched_decrypt
);

#[rstest]
#[case::registers_left_full(dirty_decrypt_registers as Routine, Left::Registers)]
#[case::frame_left_full(dirty_decrypt_frame as Routine, Left::Frame)]
#[case::nothing_ran(untouched_decrypt as Routine, Left::Everything)]
#[case::real(redoubt_aegis128l_decrypt as Routine, Left::Nothing)]
fn test_decrypt_leaves_the_residue_its_case_declares(#[case] routine: Routine, #[case] left: Left) {
    let routine = core::hint::black_box(routine);
    let (key, nonce) = material();

    for aad_len in AAD_LENGTHS {
        for data_len in DATA_LENGTHS {
            let aad = said(aad_len);
            let mut data = said(data_len);
            let mut tag = [0u8; TAG_SIZE];

            // SAFETY: as above. What `data` holds on the way in is not a
            // ciphertext anybody sealed, which changes the answer and not what
            // is measured here.
            let (registers, frame) = unsafe {
                redoubt_aegis128l_dirty_registers();
                redoubt_aegis128l_dirty_frame(0);
                measure!(
                    routine,
                    key.as_ptr(),
                    nonce.as_ptr(),
                    aad.as_ptr(),
                    aad_len,
                    data.as_mut_ptr(),
                    data_len,
                    tag.as_mut_ptr(),
                )
            };

            assert_residue(registers, frame, left, takes_a_frame(aad_len, data_len));
        }
    }
}
