// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The two verifiers, each swept over the whole of what it claims to look at:
//! every register in the budget one at a time, every byte of the frame one at
//! a time, and a positive for each.
//!
//! Every test in the parent reads a verdict one of these gives, so here they
//! are the thing under test and nothing below calls a routine.

use super::{
    redoubt_poly1305_clean_frame, redoubt_poly1305_dirty_frame,
    redoubt_poly1305_frame_is_zeroized, redoubt_poly1305_registers_are_zeroized,
};

const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

// === === === === === === === === === ===
// redoubt_poly1305_registers_are_zeroized
// === === === === === === === === === ===

#[cfg(target_arch = "x86_64")]
mod dirty_register {
    use super::{POISON, redoubt_poly1305_registers_are_zeroized};

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
                        verifier = sym redoubt_poly1305_registers_are_zeroized,
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
                verifier = sym redoubt_poly1305_registers_are_zeroized,
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
    use super::{POISON, redoubt_poly1305_registers_are_zeroized};

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
                        verifier = sym redoubt_poly1305_registers_are_zeroized,
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
                verifier = sym redoubt_poly1305_registers_are_zeroized,
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
// redoubt_poly1305_frame_is_zeroized
// === === === === === === === === === ===

/// The frame every routine takes, as the layout at the top of the assembly
/// declares it.
const FRAME: usize = 160;

/// One call per byte: leave that one and nothing else, and ask.
///
/// Every routine that takes a frame will read a verdict this gives, and a
/// verdict about a byte it never looks at would be a clean bill of health for
/// memory nobody inspected. A hundred and sixty is cheap and it is the only
/// way to know it reads all of them — an off-by-one at either end, against the
/// return address sitting next door, shows up here and nowhere else.
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

        assert_ne!(dirty, 0, "byte {at} of the frame reads as empty");
    }
}

/// The other way round, and the reason the sweep above means anything.
///
/// A verifier that answered "dirty" whatever it was handed would pass every
/// one of those hundred and sixty.
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
