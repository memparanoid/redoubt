// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each routine in the assembly leaves behind, and whether the two
//! verifiers that answer that can see anything at all.
//!
//! The verifiers come first and are the thing under test: swept over the whole
//! of what each claims to look at — every register in the budget one at a time,
//! every byte of the frame one at a time — with a positive for each. Then the
//! writers they are swept with, captured rather than asked, because an OR cannot
//! say which element carried it. Nothing in that half calls a routine.
//!
//! The routines come after, and there the verifiers are taken as read. What is
//! measured is the routine, and only what it left: whether it authenticates
//! correctly is settled where the published tags are run against every backend.
//! An assertion about an answer would make every one of those tests two tests.
//!
//! Four cases per routine, the three negatives first and the real one last,
//! because the negatives are what make it mean anything. Two of them leave a
//! residue of their own; the third leaves the machine exactly as it arrived,
//! which is what says the reading is about the routine and not about the call
//! site having tidied up.
//!
//! The dirtying goes first. The selected routine and both verifiers then run in
//! one assembly block, so Rust cannot insert work before the measurement. The
//! register verdict is kept in a callee-saved register while the frame is
//! scanned; that move neither changes the stack pointer nor touches the frame.
//!
//! These are not claims about kernel signal frames, swap, dumps, or the input
//! and output the caller owns.

use std::vec::Vec;

use rstest::rstest;

use redoubt_aead_v2_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

use crate::consts::LIMBS;

// The assembly, in the order the file declares it: the entry points the backend
// calls, then the probe, which nothing in production calls.
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

// === === === === === === === === === ===
// What differs between the two targets
// === === === === === === === === === ===
//
// Everything below this section reads the same for both, and that is the point:
// the tests are the same claims about two implementations of one thing, so a
// case added to one target and not the other is a target that quietly has less
// cover. Here the instructions differ; there the reasoning does not.

/// What the register writer leaves, and what the verifier therefore has to
/// report.
const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// The one byte the frame writer leaves, at the offset it was asked for.
const LEFT_BYTE: u8 = 0x5c;

/// The frame every routine takes, as the layout at the top of the assembly
/// declares it. Both targets reach the same width.
const FRAME: usize = 160;

/// The budget, in the order the list at the top of the assembly names it.
///
/// Both files have to say it, and only one of them can be the assembly: what
/// this one buys is that a register missing from the wipe is named when the
/// capture below fails, rather than reported as an index.
#[cfg(target_arch = "x86_64")]
const BUDGET: [&str; 9] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];

#[cfg(target_arch = "aarch64")]
const BUDGET: [&str; 18] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17",
];

/// Empty every register of the budget, in one line each.
///
/// Written out rather than looped, because a loop needs a counter and the
/// counter is one of the registers being emptied.
#[cfg(target_arch = "x86_64")]
macro_rules! empty_the_registers {
    () => {
        "xor rax, rax
         xor rcx, rcx
         xor rdx, rdx
         xor rsi, rsi
         xor rdi, rdi
         xor r8, r8
         xor r9, r9
         xor r10, r10
         xor r11, r11"
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! empty_the_registers {
    () => {
        "mov x0, xzr
         mov x1, xzr
         mov x2, xzr
         mov x3, xzr
         mov x4, xzr
         mov x5, xzr
         mov x6, xzr
         mov x7, xzr
         mov x8, xzr
         mov x9, xzr
         mov x10, xzr
         mov x11, xzr
         mov x12, xzr
         mov x13, xzr
         mov x14, xzr
         mov x15, xzr
         mov x16, xzr
         mov x17, xzr"
    };
}

/// One test per register: fill that one and nothing else, and ask.
///
/// Every other test here reads a verdict the verifier gives. A verdict about a
/// register it never actually looks at would be a clean bill of health for a
/// register nobody checked, and there is no way to find that out except by
/// dirtying them one at a time.
///
/// The others are emptied first, which is what makes the answer about this one.
/// Left as the compiler happened to leave them, a verdict of "dirty" would be a
/// verdict about whichever of them held something, and every one of these tests
/// would pass without the register in its own name ever being looked at.
///
/// The poison is an immediate and not an operand. Handed over in a register, the
/// compiler is free to pick one of the caller-saved ones — `lateout` says they
/// are written late, not that they are unavailable before — and the emptying
/// above would wipe it on the way past.
#[cfg(target_arch = "x86_64")]
macro_rules! test_dirty_register_is_seen {
    ($name:ident, $register:tt) => {
        #[test]
        fn $name() {
            let dirty: u64;

            // SAFETY: the callee takes no argument and returns in the return
            // register, so the only registers that matter are the ones named
            // here, and every caller-saved one is declared clobbered.
            unsafe {
                core::arch::asm!(
                    empty_the_registers!(),
                    concat!("mov ", $register, ", {poison}"),
                    "call {verifier}",
                    poison = const POISON,
                    verifier = sym redoubt_poly1305_registers_are_zeroized,
                    lateout("rax") dirty,
                    clobber_abi("C"),
                );
            }

            assert_eq!(
                dirty, POISON,
                concat!("a dirty ", $register, " does not reach the answer")
            );
        }
    };
}

/// One test per register, where the pattern takes four instructions to build.
///
/// A sixty-four bit value does not fit in an immediate here, so it is assembled
/// in place a quarter at a time — and still in place rather than in a register.
/// Handed over in one, the compiler is free to pick a caller-saved register:
/// `lateout` says they are written late, not that they are unavailable before,
/// and the emptying above would wipe the pattern on the way past.
#[cfg(target_arch = "aarch64")]
macro_rules! test_dirty_register_is_seen {
    ($name:ident, $register:tt) => {
        #[test]
        fn $name() {
            let dirty: u64;

            // SAFETY: the callee takes no argument and returns in the return
            // register, so the only registers that matter are the ones named
            // here, and every caller-saved one is declared clobbered.
            unsafe {
                core::arch::asm!(
                    empty_the_registers!(),
                    concat!("movz ", $register, ", #0xa5a5"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #16"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #32"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #48"),
                    "bl {verifier}",
                    verifier = sym redoubt_poly1305_registers_are_zeroized,
                    lateout("x0") dirty,
                    clobber_abi("C"),
                );
            }

            assert_eq!(
                dirty, POISON,
                concat!("a dirty ", $register, " does not reach the answer")
            );
        }
    };
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
/// The arguments are given by position and never by register name. A call site
/// that named registers would be a call site that differs per target, and the
/// point of this section is that nothing below it does.
///
/// One arm per arity the routines here have. An arity nobody uses is an arm
/// nobody writes, and an arity written wrong is a call site that does not
/// compile rather than one that measures the wrong thing.
///
/// The caller must uphold the routine's pointer and length preconditions. Both
/// verifiers preserve r12, where the first verdict waits for the second.
/// Declaring that output makes Rust preserve its caller's value.
#[cfg(target_arch = "x86_64")]
macro_rules! measure {
    ($routine:expr, $a0:expr, $a1:expr, $a2:expr $(,)?) => {
        measure!(@call $routine, [("rdi") $a0, ("rsi") $a1, ("rdx") $a2])
    };
    ($routine:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr $(,)?) => {
        measure!(@call $routine,
                 [("rdi") $a0, ("rsi") $a1, ("rdx") $a2, ("rcx") $a3, ("r8") $a4, ("r9") $a5])
    };
    (@call $routine:expr, [$(($register:tt) $argument:expr),* $(,)?]) => {{
        let registers: u64;
        let frame: u64;

        core::arch::asm!(
            "call r11",
            "call {register_probe}",
            "mov r12, rax",
            "call {frame_probe}",
            register_probe = sym redoubt_poly1305_registers_are_zeroized,
            frame_probe = sym redoubt_poly1305_frame_is_zeroized,
            inlateout("r11") $routine => _,
            $(inlateout($register) $argument => _,)*
            lateout("r12") registers,
            lateout("rax") frame,
            clobber_abi("C"),
        );

        (registers, frame)
    }};
}

/// Call the selected routine with its ABI arguments and immediately measure it.
///
/// Both verdicts are moved out of the return register before they can be
/// overwritten, into x20 and x21. Left in x0, the first would be gone by the
/// second call and the second would collide with an argument.
#[cfg(target_arch = "aarch64")]
macro_rules! measure {
    ($routine:expr, $a0:expr, $a1:expr, $a2:expr $(,)?) => {
        measure!(@call $routine, [("x0") $a0, ("x1") $a1, ("x2") $a2])
    };
    ($routine:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr $(,)?) => {
        measure!(@call $routine,
                 [("x0") $a0, ("x1") $a1, ("x2") $a2, ("x3") $a3, ("x4") $a4, ("x5") $a5])
    };
    (@call $routine:expr, [$(($register:tt) $argument:expr),* $(,)?]) => {{
        let registers: u64;
        let frame: u64;

        core::arch::asm!(
            "blr x16",
            "bl {register_probe}",
            "mov x20, x0",
            "bl {frame_probe}",
            "mov x21, x0",
            register_probe = sym redoubt_poly1305_registers_are_zeroized,
            frame_probe = sym redoubt_poly1305_frame_is_zeroized,
            inlateout("x16") $routine => _,
            $(inlateout($register) $argument => _,)*
            lateout("x20") registers,
            lateout("x21") frame,
            clobber_abi("C"),
        );

        (registers, frame)
    }};
}

// === === === === === === === === === ===
// redoubt_poly1305_registers_are_zeroized
// === === === === === === === === === ===

/// One invocation per entry of `BUDGET`, written by hand.
///
/// A register named in the list and missing here is a register the capture
/// below reports filled while the verifier is never asked about it — green on
/// both sides, and nobody looking at that register. The count at the end of each
/// block is what keeps the two together.
#[cfg(target_arch = "x86_64")]
mod every_register {
    use super::{POISON, redoubt_poly1305_registers_are_zeroized};

    test_dirty_register_is_seen!(test_rax_is_seen, "rax");
    test_dirty_register_is_seen!(test_rcx_is_seen, "rcx");
    test_dirty_register_is_seen!(test_rdx_is_seen, "rdx");
    test_dirty_register_is_seen!(test_rsi_is_seen, "rsi");
    test_dirty_register_is_seen!(test_rdi_is_seen, "rdi");
    test_dirty_register_is_seen!(test_r8_is_seen, "r8");
    test_dirty_register_is_seen!(test_r9_is_seen, "r9");
    test_dirty_register_is_seen!(test_r10_is_seen, "r10");
    test_dirty_register_is_seen!(test_r11_is_seen, "r11");

    pub(super) const TESTS: usize = 9;
}

#[cfg(target_arch = "aarch64")]
mod every_register {
    use super::{POISON, redoubt_poly1305_registers_are_zeroized};

    test_dirty_register_is_seen!(test_x0_is_seen, "x0");
    test_dirty_register_is_seen!(test_x1_is_seen, "x1");
    test_dirty_register_is_seen!(test_x2_is_seen, "x2");
    test_dirty_register_is_seen!(test_x3_is_seen, "x3");
    test_dirty_register_is_seen!(test_x4_is_seen, "x4");
    test_dirty_register_is_seen!(test_x5_is_seen, "x5");
    test_dirty_register_is_seen!(test_x6_is_seen, "x6");
    test_dirty_register_is_seen!(test_x7_is_seen, "x7");
    test_dirty_register_is_seen!(test_x8_is_seen, "x8");
    test_dirty_register_is_seen!(test_x9_is_seen, "x9");
    test_dirty_register_is_seen!(test_x10_is_seen, "x10");
    test_dirty_register_is_seen!(test_x11_is_seen, "x11");
    test_dirty_register_is_seen!(test_x12_is_seen, "x12");
    test_dirty_register_is_seen!(test_x13_is_seen, "x13");
    test_dirty_register_is_seen!(test_x14_is_seen, "x14");
    test_dirty_register_is_seen!(test_x15_is_seen, "x15");
    test_dirty_register_is_seen!(test_x16_is_seen, "x16");
    test_dirty_register_is_seen!(test_x17_is_seen, "x17");

    pub(super) const TESTS: usize = 18;
}

/// Every register the list names has a test of its own.
#[test]
fn test_the_list_names_as_many_registers_as_there_are_tests() {
    assert_eq!(BUDGET.len(), every_register::TESTS);
}

/// The other way round, and the reason the rest mean anything.
///
/// A verifier that answered "dirty" whatever it was handed would pass every
/// test above, so one of them has to hand it a machine that is actually clean.
#[test]
fn test_an_empty_register_file_reads_as_empty() {
    let dirty: u64;

    #[cfg(target_arch = "x86_64")]
    // SAFETY: the callee takes no argument and returns in the return register.
    // Every caller-saved register is emptied here before the call and declared
    // clobbered after it.
    unsafe {
        core::arch::asm!(
            empty_the_registers!(),
            "call {verifier}",
            verifier = sym redoubt_poly1305_registers_are_zeroized,
            lateout("rax") dirty,
            clobber_abi("C"),
        );
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: the same, with the answer arriving in x0 instead of rax.
    unsafe {
        core::arch::asm!(
            empty_the_registers!(),
            "bl {verifier}",
            verifier = sym redoubt_poly1305_registers_are_zeroized,
            lateout("x0") dirty,
            clobber_abi("C"),
        );
    }

    assert_eq!(dirty, 0, "an empty register file reads as dirty");
}

// === === === === === === === === === ===
// redoubt_poly1305_frame_is_zeroized
// === === === === === === === === === ===

/// One call per byte: leave that one and nothing else, and ask.
///
/// Every routine that takes a frame will read a verdict this gives, and a
/// verdict about a byte it never looks at would be a clean bill of health for
/// memory nobody inspected. A frame's worth of calls is cheap and it is the only
/// way to know it reads all of them — an off-by-one at either end, against
/// whatever sits next door, shows up here and nowhere else.
///
/// The pair is called with nothing in between, which is the other thing being
/// measured: if anything ran there, the frame the verifier reads would not be
/// the one the writer left.
#[test]
fn test_a_byte_left_anywhere_in_the_frame_is_seen() {
    for at in 0..FRAME {
        // SAFETY: the target writes one byte inside the frame it allocated,
        // and the verifier reads the frame the call before it released.
        let dirty = unsafe {
            redoubt_poly1305_dirty_frame(at);
            redoubt_poly1305_frame_is_zeroized()
        };

        assert_eq!(
            dirty,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}

/// The other way round, and the reason the sweep above means anything.
#[test]
fn test_a_frame_written_and_emptied_reads_as_empty() {
    // SAFETY: the target fills the frame it allocated and empties it again,
    // and the verifier reads what it released.
    let dirty = unsafe {
        redoubt_poly1305_clean_frame();
        redoubt_poly1305_frame_is_zeroized()
    };

    // Assert zeroization!
    assert_eq!(dirty, 0, "a frame that was emptied reads as full");
}

// === === === === === === === === === ===
// redoubt_poly1305_dirty_registers
// === === === === === === === === === ===

/// The writer must fill every register in the budget, not merely some of them.
///
/// The sweep above establishes that the verifier sees any one register. This is
/// the other half of that instrument: the negatives further down read "something
/// is still full", and a writer short by one register would let them pass while
/// never dirtying the register the routine under test failed to wipe.
///
/// Capture the registers directly rather than asking the verifier: an OR cannot
/// tell which of them carried the answer. They are emptied first, so an equality
/// here can only have come from the writer.
#[test]
fn test_dirty_registers_fills_every_register_in_the_budget() {
    let mut actual = [0_u64; BUDGET.len()];

    #[cfg(target_arch = "x86_64")]
    // SAFETY: the callee takes no argument, and r12 is outside the budget it
    // fills, so the destination survives the call. `actual` is as long as the
    // budget, and the stores below cover it exactly once each.
    unsafe {
        core::arch::asm!(
            empty_the_registers!(),
            "call {writer}",
            "mov [r12], rax",
            "mov [r12 + 8], rcx",
            "mov [r12 + 16], rdx",
            "mov [r12 + 24], rsi",
            "mov [r12 + 32], rdi",
            "mov [r12 + 40], r8",
            "mov [r12 + 48], r9",
            "mov [r12 + 56], r10",
            "mov [r12 + 64], r11",
            writer = sym redoubt_poly1305_dirty_registers,
            inlateout("r12") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: the same, with x20 outside the budget instead of r12.
    unsafe {
        core::arch::asm!(
            empty_the_registers!(),
            "bl {writer}",
            "stp x0, x1, [x20]",
            "stp x2, x3, [x20, #16]",
            "stp x4, x5, [x20, #32]",
            "stp x6, x7, [x20, #48]",
            "stp x8, x9, [x20, #64]",
            "stp x10, x11, [x20, #80]",
            "stp x12, x13, [x20, #96]",
            "stp x14, x15, [x20, #112]",
            "stp x16, x17, [x20, #128]",
            writer = sym redoubt_poly1305_dirty_registers,
            inlateout("x20") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(
            value, POISON,
            "{} came back from the writer empty",
            BUDGET[at]
        );
    }
}

// === === === === === === === === === ===
// redoubt_poly1305_dirty_frame
// === === === === === === === === === ===

/// The writer must leave exactly one byte, even on a previously full frame.
///
/// Capture the bytes directly rather than asking the verifier: that answer
/// cannot distinguish the requested byte from residue somewhere else. Filling,
/// calling and capturing stay in one assembly block, with every stack access
/// inside a region reserved by this caller or by the writer itself.
#[test]
fn test_dirty_frame_clears_every_byte_except_the_requested_one() {
    for at in 0..FRAME {
        let mut actual = [0xff_u8; FRAME];

        #[cfg(target_arch = "x86_64")]
        // SAFETY: at is inside the writer's frame, and actual covers every
        // captured byte. r12 holds its pointer across the call; the writer
        // preserves it. The reservation keeps call alignment and includes eight
        // bytes below the frame plus the return-address slot: the writer's
        // frame is [rsp + 8, rsp + 8 + FRAME) after reserving again.
        unsafe {
            core::arch::asm!(
                "sub rsp, {window}",
                "mov rax, {poison}",
                "xor ecx, ecx",
                "2:",
                "mov [rsp + rcx + 8], rax",
                "add rcx, 8",
                "cmp rcx, {frame}",
                "jb 2b",
                "add rsp, {window}",
                "call {writer}",
                "sub rsp, {window}",
                "xor ecx, ecx",
                "3:",
                "mov al, [rsp + rcx + 8]",
                "mov [r12 + rcx], al",
                "mov byte ptr [rsp + rcx + 8], 0",
                "inc rcx",
                "cmp rcx, {frame}",
                "jb 3b",
                "add rsp, {window}",
                window = const FRAME + 16,
                frame = const FRAME,
                poison = const POISON,
                writer = sym redoubt_poly1305_dirty_frame,
                inlateout("rdi") at => _,
                inlateout("r12") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        #[cfg(target_arch = "aarch64")]
        // SAFETY: at and actual satisfy the same bounds as above. x20 holds the
        // destination across the call and is preserved by the writer. `bl` uses
        // x30, not a stack slot, so reserving FRAME again gives exactly the
        // writer's former frame.
        unsafe {
            core::arch::asm!(
                "sub sp, sp, #{frame}",
                "movz x1, #0xa5a5",
                "movk x1, #0xa5a5, lsl #16",
                "movk x1, #0xa5a5, lsl #32",
                "movk x1, #0xa5a5, lsl #48",
                "mov x2, xzr",
                "2:",
                "str x1, [sp, x2]",
                "add x2, x2, #8",
                "cmp x2, #{frame}",
                "b.lo 2b",
                "add sp, sp, #{frame}",
                "bl {writer}",
                "sub sp, sp, #{frame}",
                "mov x2, xzr",
                "3:",
                "ldrb w1, [sp, x2]",
                "strb w1, [x20, x2]",
                "strb wzr, [sp, x2]",
                "add x2, x2, #1",
                "cmp x2, #{frame}",
                "b.lo 3b",
                "add sp, sp, #{frame}",
                frame = const FRAME,
                writer = sym redoubt_poly1305_dirty_frame,
                inlateout("x0") at => _,
                inlateout("x20") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        for (byte, &value) in actual.iter().enumerate() {
            assert_eq!(
                value,
                if byte == at { LEFT_BYTE } else { 0 },
                "requested byte {at}, captured byte {byte}",
            );
        }
    }
}

// === === === === === === === === === ===
// What the routines leave
// === === === === === === === === === ===

/// The clamped key the two routines after `init` are given.
///
/// It comes from `init` itself rather than from the other backend: what these
/// routines leave behind does not depend on the value being right, and asking
/// the Rust side for it would put a second implementation in a file that is
/// about one.
fn clamped() -> ([u32; LIMBS], [u8; BLOCK_SIZE]) {
    let key: [u8; KEY_SIZE] = core::array::from_fn(|at| 0x40 + at as u8);
    let mut r = [0_u32; LIMBS];
    let mut s = [0_u8; BLOCK_SIZE];

    // SAFETY: the three arrays are disjoint and have the widths the routine
    // reads and writes.
    unsafe { redoubt_poly1305_init(r.as_mut_ptr(), s.as_mut_ptr(), key.as_ptr()) };

    (r, s)
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
    let mut r = [0_u32; LIMBS];
    let mut s = [0_u8; BLOCK_SIZE];

    let r = r.as_mut_ptr();
    let s = s.as_mut_ptr();
    let key = key.as_ptr();

    // SAFETY: the three arrays are disjoint and have the widths the routine
    // reads and writes.
    let (registers, frame) = unsafe {
        redoubt_poly1305_dirty_registers();
        redoubt_poly1305_dirty_frame(0);
        measure!(routine, r, s, key)
    };

    // The clamp takes no frame; its pre-dirtied byte must remain.
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

            let mut acc = [0_u64; LIMBS];
            let mut block = [0_u8; BLOCK_SIZE];
            let mut held = filled;
            block[..filled].fill(0xc3);

            let acc = acc.as_mut_ptr();
            let key = r.as_ptr();
            let block = block.as_mut_ptr();
            let held = &raw mut held;
            let said = said.as_ptr();

            // SAFETY: every pointer is to storage of the width the routine
            // reads or writes, `said` is as long as the length beside it, and
            // `filled` is no greater than the block it indexes.
            let (registers, frame) = unsafe {
                redoubt_poly1305_dirty_registers();
                redoubt_poly1305_dirty_frame(0);
                measure!(routine, acc, key, block, held, said, length)
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
        let mut acc = [0_u64; LIMBS];
        let mut tag = [0_u8; TAG_SIZE];

        let acc = acc.as_mut_ptr();
        let key = r.as_ptr();
        let block = s.as_ptr();
        let said = said.as_ptr();
        let tag = tag.as_mut_ptr();

        // SAFETY: every pointer is to an array of the width the routine reads
        // or writes, and `said` is as long as the length beside it.
        let (registers, frame) = unsafe {
            redoubt_poly1305_dirty_registers();
            redoubt_poly1305_dirty_frame(0);
            measure!(routine, acc, key, block, said, length, tag)
        };

        assert_residue(registers, frame, left, true);
    }
}

// === === === === === === === === === ===
// What the measurement reads
// === === === === === === === === === ===
//
// The window each measurement dirties has to be the window its verifier reads.
//
// The sweep over `dirty_frame` calls the writer and the verifier one after the
// other with nothing between them, so it cannot see a call site that moved the
// stack pointer between the two. These go through the measurement instead, and
// against the stand-in that does nothing at all — so what the verifier reports
// is the byte the writer left, at every offset it could be left at.
//
// A reservation a measurement forgot to account for shows up at whichever end
// the window slid off, and nowhere else. The byte at offset zero survives a
// slide in either direction, and offset zero is the only one the cases above ask
// about.
//
// Every argument is settled before the writer runs. What is computed between the
// writer and the block is Rust reaching for the stack the writer just filled,
// and the verifier reads that back as residue the writer did not leave.
//
// The answer is asserted exactly and not merely as "something was found". The
// verifier ORs the window a word at a time, so one byte left in it comes back as
// that byte and nothing else — and a window that slid reads bytes nobody wrote,
// which come back as whatever was there.

/// What the verifier answers when the only thing left in the window is the byte
/// the writer put at `at`.
fn only_the_byte_at(at: usize) -> u64 {
    u64::from(LEFT_BYTE) << (8 * (at % 8))
}

/// No offset expects an empty window.
///
/// Every sweep above asserts what this returns, and cannot check it: the only
/// other thing that knows where the byte lands is the verifier, which is what
/// those sweeps are asking about. So what is asked here is the one property that
/// would make the sweeps lie rather than fail — an expected answer of zero turns
/// "the verifier found the byte" into "the verifier found nothing", and that
/// reads as a pass at exactly the offset the byte went missing.
#[test]
fn test_no_offset_expects_an_empty_window() {
    for at in 0..FRAME {
        assert_ne!(only_the_byte_at(at), 0, "offset {at}");
    }
}

#[test]
fn test_the_measurement_of_init_reads_the_window_the_writer_filled() {
    let key: [u8; KEY_SIZE] = core::array::from_fn(|at| 0x40 + at as u8);
    let mut r = [0_u32; LIMBS];
    let mut s = [0_u8; BLOCK_SIZE];

    let r = r.as_mut_ptr();
    let s = s.as_mut_ptr();
    let key = key.as_ptr();

    for at in 0..FRAME {
        // SAFETY: at is inside the writer's frame, and the stand-in never
        // dereferences what it is handed.
        let (_, frame) = unsafe {
            redoubt_poly1305_dirty_frame(at);
            measure!(untouched_init as Init, r, s, key)
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}

#[test]
fn test_the_measurement_of_update_reads_the_window_the_writer_filled() {
    let (r, _) = clamped();
    let said: Vec<u8> = (0..65_u8).collect();
    let mut acc = [0_u64; LIMBS];
    let mut block = [0_u8; BLOCK_SIZE];
    let mut held = 0_usize;

    let acc = acc.as_mut_ptr();
    let key = r.as_ptr();
    let block = block.as_mut_ptr();
    let held = &raw mut held;
    let length = said.len();
    let said = said.as_ptr();

    for at in 0..FRAME {
        // SAFETY: as above.
        let (_, frame) = unsafe {
            redoubt_poly1305_dirty_frame(at);
            measure!(
                untouched_update as Update,
                acc,
                key,
                block,
                held,
                said,
                length
            )
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}

#[test]
fn test_the_measurement_of_finalize_reads_the_window_the_writer_filled() {
    let (r, s) = clamped();
    let said: Vec<u8> = (0..65_u8).collect();
    let mut acc = [0_u64; LIMBS];
    let mut tag = [0_u8; TAG_SIZE];

    let acc = acc.as_mut_ptr();
    let key = r.as_ptr();
    let block = s.as_ptr();
    let length = said.len();
    let said = said.as_ptr();
    let tag = tag.as_mut_ptr();

    for at in 0..FRAME {
        // SAFETY: as above.
        let (_, frame) = unsafe {
            redoubt_poly1305_dirty_frame(at);
            measure!(
                untouched_finalize as Finalize,
                acc,
                key,
                block,
                said,
                length,
                tag
            )
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}
