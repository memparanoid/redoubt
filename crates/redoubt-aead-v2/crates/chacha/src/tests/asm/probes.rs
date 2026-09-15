// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The two verifiers, each swept over the whole of what it claims to look at:
//! every register in the budget one at a time, every byte of the frame one at
//! a time, and a positive for each. Then the two writers they are swept with,
//! captured rather than asked: an OR cannot say which element carried it.
//!
//! Every test in the parent reads a verdict one of these gives, so here they
//! are the thing under test and nothing below calls a routine.

use super::{
    redoubt_chacha_clean_frame, redoubt_chacha_dirty_frame, redoubt_chacha_dirty_registers,
    redoubt_chacha_frame_is_zeroized, redoubt_chacha_registers_are_zeroized,
};

const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// The frame the stream routines take, as the layout at the top of the
/// assembly declares it. The two architectures do not agree: x86-64 keeps four
/// working words in registers and the rest here, aarch64 keeps all sixteen.
#[cfg(target_arch = "x86_64")]
const FRAME: usize = 160;

#[cfg(target_arch = "aarch64")]
const FRAME: usize = 96;

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

// === === === === === === === === === ===
// redoubt_chacha_registers_are_zeroized
// === === === === === === === === === ===

#[cfg(target_arch = "x86_64")]
mod dirty_register {
    use super::{POISON, redoubt_chacha_registers_are_zeroized};

    /// One test per register: fill that one and nothing else, and ask.
    ///
    /// Every other test here reads a verdict the verifier gives. A verdict
    /// about a register it never actually looks at would be a clean bill of
    /// health for a register nobody checked, and there is no way to find that
    /// out except by dirtying them one at a time.
    ///
    /// The eight others are emptied first, which is what makes the answer
    /// about this one. Left as the compiler happened to leave them, a verdict
    /// of "dirty" would be a verdict about whichever of them held something,
    /// and every one of these tests would pass without the register in its own
    /// name ever being looked at.
    ///
    /// The poison is an immediate and not an operand. Handed over in a
    /// register, the compiler is free to pick one of the caller-saved ones —
    /// `lateout` says they are written late, not that they are unavailable
    /// before — and the emptying above would wipe it on the way past.
    macro_rules! test_dirty_register_is_seen {
        ($name:ident, $register:tt) => {
            #[test]
            fn $name() {
                let dirty: u64;

                // SAFETY: the callee takes no argument and returns in the
                // return register, so the only registers that matter are the
                // ones named here, and every caller-saved one is declared
                // clobbered.
                unsafe {
                    core::arch::asm!(
                        "xor rax, rax",
                        "xor rcx, rcx",
                        "xor rdx, rdx",
                        "xor rsi, rsi",
                        "xor rdi, rdi",
                        "xor r8, r8",
                        "xor r9, r9",
                        "xor r10, r10",
                        "xor r11, r11",
                        concat!("mov ", $register, ", {poison}"),
                        "call {verifier}",
                        poison = const POISON,
                        verifier = sym redoubt_chacha_registers_are_zeroized,
                        lateout("rax") dirty,
                        lateout("rcx") _, lateout("rdx") _, lateout("rsi") _,
                        lateout("rdi") _, lateout("r8") _, lateout("r9") _,
                        lateout("r10") _, lateout("r11") _,
                    );
                }

                assert_eq!(
                    dirty, POISON,
                    concat!("a dirty ", $register, " does not reach the answer")
                );
            }
        };
    }

    /// The other way round, and the reason the rest mean anything.
    ///
    /// A verifier that answered "dirty" whatever it was handed would pass
    /// every test below, so one of them has to hand it a machine that is
    /// actually clean.
    #[test]
    fn test_an_empty_register_file_reads_as_empty() {
        let dirty: u64;

        // SAFETY: the callee takes no argument and returns in the return
        // register. Every caller-saved register is emptied here before the
        // call and declared clobbered after it.
        unsafe {
            core::arch::asm!(
                "xor rax, rax",
                "xor rcx, rcx",
                "xor rdx, rdx",
                "xor rsi, rsi",
                "xor rdi, rdi",
                "xor r8, r8",
                "xor r9, r9",
                "xor r10, r10",
                "xor r11, r11",
                "call {verifier}",
                verifier = sym redoubt_chacha_registers_are_zeroized,
                lateout("rax") dirty,
                lateout("rcx") _, lateout("rdx") _, lateout("rsi") _,
                lateout("rdi") _, lateout("r8") _, lateout("r9") _,
                lateout("r10") _, lateout("r11") _,
            );
        }

        assert_eq!(dirty, 0, "an empty register file reads as dirty");
    }

    test_dirty_register_is_seen!(test_rax_is_seen, "rax");
    test_dirty_register_is_seen!(test_rcx_is_seen, "rcx");
    test_dirty_register_is_seen!(test_rdx_is_seen, "rdx");
    test_dirty_register_is_seen!(test_rsi_is_seen, "rsi");
    test_dirty_register_is_seen!(test_rdi_is_seen, "rdi");
    test_dirty_register_is_seen!(test_r8_is_seen, "r8");
    test_dirty_register_is_seen!(test_r9_is_seen, "r9");
    test_dirty_register_is_seen!(test_r10_is_seen, "r10");
    test_dirty_register_is_seen!(test_r11_is_seen, "r11");
}

#[cfg(target_arch = "aarch64")]
mod dirty_register {
    use super::{POISON, redoubt_chacha_registers_are_zeroized};

    /// One test per register: fill that one and nothing else, and ask.
    ///
    /// Every other test here reads a verdict the verifier gives. A verdict
    /// about a register it never actually looks at would be a clean bill of
    /// health for a register nobody checked, and there is no way to find that
    /// out except by dirtying them one at a time.
    ///
    /// The seventeen others are emptied first, which is what makes the answer
    /// about this one. Left as the compiler happened to leave them, a verdict
    /// of "dirty" would be a verdict about whichever of them held something,
    /// and every one of these tests would pass without the register in its own
    /// name ever being looked at.
    ///
    /// The poison is built in place with four immediates rather than handed
    /// over in a register. In a register the compiler is free to pick one of
    /// the caller-saved ones — `lateout` says they are written late, not that
    /// they are unavailable before — and the emptying above would wipe it on
    /// the way past.
    macro_rules! test_dirty_register_is_seen {
        ($name:ident, $register:tt) => {
            #[test]
            fn $name() {
                let dirty: u64;

                // SAFETY: the callee takes no argument and returns in the
                // return register, so the only registers that matter are the
                // ones named here, and every caller-saved one is declared
                // clobbered.
                unsafe {
                    core::arch::asm!(
                        "mov x0, xzr", "mov x1, xzr", "mov x2, xzr",
                        "mov x3, xzr", "mov x4, xzr", "mov x5, xzr",
                        "mov x6, xzr", "mov x7, xzr", "mov x8, xzr",
                        "mov x9, xzr", "mov x10, xzr", "mov x11, xzr",
                        "mov x12, xzr", "mov x13, xzr", "mov x14, xzr",
                        "mov x15, xzr", "mov x16, xzr", "mov x17, xzr",
                        concat!("mov ", $register, ", #0xa5a5"),
                        concat!("movk ", $register, ", #0xa5a5, lsl #16"),
                        concat!("movk ", $register, ", #0xa5a5, lsl #32"),
                        concat!("movk ", $register, ", #0xa5a5, lsl #48"),
                        "bl {verifier}",
                        verifier = sym redoubt_chacha_registers_are_zeroized,
                        lateout("x0") dirty,
                        lateout("x1") _, lateout("x2") _, lateout("x3") _,
                        lateout("x4") _, lateout("x5") _, lateout("x6") _,
                        lateout("x7") _, lateout("x8") _, lateout("x9") _,
                        lateout("x10") _, lateout("x11") _, lateout("x12") _,
                        lateout("x13") _, lateout("x14") _, lateout("x15") _,
                        lateout("x16") _, lateout("x17") _, lateout("x30") _,
                    );
                }

                assert_eq!(
                    dirty, POISON,
                    concat!("a dirty ", $register, " does not reach the answer")
                );
            }
        };
    }

    /// The other way round, and the reason the rest mean anything.
    ///
    /// A verifier that answered "dirty" whatever it was handed would pass
    /// every test below, so one of them has to hand it a machine that is
    /// actually clean.
    #[test]
    fn test_an_empty_register_file_reads_as_empty() {
        let dirty: u64;

        // SAFETY: the callee takes no argument and returns in the return
        // register. Every caller-saved register is emptied here before the
        // call and declared clobbered after it.
        unsafe {
            core::arch::asm!(
                "mov x0, xzr", "mov x1, xzr", "mov x2, xzr", "mov x3, xzr",
                "mov x4, xzr", "mov x5, xzr", "mov x6, xzr", "mov x7, xzr",
                "mov x8, xzr", "mov x9, xzr", "mov x10, xzr", "mov x11, xzr",
                "mov x12, xzr", "mov x13, xzr", "mov x14, xzr", "mov x15, xzr",
                "mov x16, xzr", "mov x17, xzr",
                "bl {verifier}",
                verifier = sym redoubt_chacha_registers_are_zeroized,
                lateout("x0") dirty,
                lateout("x1") _, lateout("x2") _, lateout("x3") _,
                lateout("x4") _, lateout("x5") _, lateout("x6") _,
                lateout("x7") _, lateout("x8") _, lateout("x9") _,
                lateout("x10") _, lateout("x11") _, lateout("x12") _,
                lateout("x13") _, lateout("x14") _, lateout("x15") _,
                lateout("x16") _, lateout("x17") _, lateout("x30") _,
            );
        }

        assert_eq!(dirty, 0, "an empty register file reads as dirty");
    }

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
}

// === === === === === === === === === ===
// redoubt_chacha_frame_is_zeroized
// === === === === === === === === === ===

/// One call per byte: leave that one and nothing else, and ask.
///
/// Every routine that takes a frame will read a verdict this gives, and a
/// verdict about a byte it never looks at would be a clean bill of health for
/// memory nobody inspected. A frame's worth of calls is cheap and it is the
/// only way to know it reads all of them — an off-by-one at either end, against
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
            redoubt_chacha_dirty_frame(at);
            redoubt_chacha_frame_is_zeroized()
        };

        assert_ne!(dirty, 0, "byte {at} of the frame reads as empty");
    }
}

/// The other way round, and the reason the sweep above means anything.
///
/// A verifier that answered "dirty" whatever it was handed would pass every
/// one of those calls.
#[test]
fn test_a_frame_written_and_emptied_reads_as_empty() {
    // SAFETY: the target fills the frame it allocated and empties it again,
    // and the verifier reads what it released.
    let dirty = unsafe {
        redoubt_chacha_clean_frame();
        redoubt_chacha_frame_is_zeroized()
    };

    // Assert zeroization!
    assert_eq!(dirty, 0, "a frame that was emptied reads as full");
}

// === === === === === === === === === ===
// redoubt_chacha_dirty_registers
// === === === === === === === === === ===

/// The writer must fill every register in the budget, not merely some of them.
///
/// The sweep above establishes that the verifier sees any one register. This
/// is the other half of that instrument: the negatives in the parent read
/// "something is still full", and a writer short by one register would let
/// them pass while never dirtying the register the routine under test failed
/// to wipe.
///
/// Capture the registers directly rather than asking the OR verifier, for the
/// same reason the frame writer is captured below: an OR cannot tell which of
/// them carried the answer. They are emptied first, so an equality here can
/// only have come from the writer.
#[test]
fn test_dirty_registers_fills_every_register_in_the_budget() {
    let mut actual = [0u64; BUDGET.len()];

    #[cfg(target_arch = "x86_64")]
    // SAFETY: the callee takes no argument, and r12 is outside the budget it
    // fills, so the destination survives the call. `actual` is as long as the
    // budget, and the stores below cover it exactly once each.
    unsafe {
        core::arch::asm!(
            "xor rax, rax",
            "xor rcx, rcx",
            "xor rdx, rdx",
            "xor rsi, rsi",
            "xor rdi, rdi",
            "xor r8, r8",
            "xor r9, r9",
            "xor r10, r10",
            "xor r11, r11",
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
            writer = sym redoubt_chacha_dirty_registers,
            inlateout("r12") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: the same, with x20 outside the budget instead of r12.
    unsafe {
        core::arch::asm!(
            "mov x0, xzr", "mov x1, xzr", "mov x2, xzr", "mov x3, xzr",
            "mov x4, xzr", "mov x5, xzr", "mov x6, xzr", "mov x7, xzr",
            "mov x8, xzr", "mov x9, xzr", "mov x10, xzr", "mov x11, xzr",
            "mov x12, xzr", "mov x13, xzr", "mov x14, xzr", "mov x15, xzr",
            "mov x16, xzr", "mov x17, xzr",
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
            writer = sym redoubt_chacha_dirty_registers,
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
// redoubt_chacha_dirty_frame
// === === === === === === === === === ===

/// The writer must leave exactly one byte, even on a previously full frame.
///
/// Capture the bytes directly rather than asking the OR verifier: that answer
/// cannot distinguish the requested byte from residue somewhere else. Filling,
/// calling and capturing stay in one assembly block, with every stack access
/// inside a region reserved by this caller or by the writer itself.
#[test]
fn test_dirty_frame_clears_every_byte_except_the_requested_one() {
    for at in 0..FRAME {
        let mut actual = [0xffu8; FRAME];

        #[cfg(target_arch = "x86_64")]
        // SAFETY: at is inside the writer's frame, and actual covers every
        // captured byte. r12 holds its pointer across the call; the writer
        // preserves it. The reservation keeps call alignment and includes
        // eight bytes below the frame plus the return-address slot: the
        // writer's frame is [rsp + 8, rsp + 8 + FRAME) after reserving again.
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
                writer = sym redoubt_chacha_dirty_frame,
                inlateout("rdi") at => _,
                inlateout("r12") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        #[cfg(target_arch = "aarch64")]
        // SAFETY: at and actual satisfy the same bounds as above. x20 holds
        // the destination across the call and is preserved by the writer.
        // The frame is sixteen-byte aligned. bl uses x30, not a stack slot,
        // so reserving FRAME again gives exactly the writer's former frame.
        unsafe {
            core::arch::asm!(
                "sub sp, sp, #{frame}",
                "mov x1, #0xa5a5",
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
                writer = sym redoubt_chacha_dirty_frame,
                inlateout("x0") at => _,
                inlateout("x20") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        for (byte, &value) in actual.iter().enumerate() {
            assert_eq!(
                value,
                if byte == at { 0x5c } else { 0 },
                "requested byte {at}, captured byte {byte}",
            );
        }
    }
}
