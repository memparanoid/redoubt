// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The two verifiers, each swept over the whole of what it claims to look at:
//! every register in the budget one at a time, every byte of the frame one at
//! a time, and a positive for each. Then the two writers they are swept with,
//! captured rather than asked: an OR cannot say which element carried it.
//!
//! Every test in `asm` reads a verdict one of these gives, so here they are the
//! thing under test and nothing below calls a routine.
//!
//! The state of AEGIS lives in the vector registers and nowhere else, so those
//! are in the budget as well as the general ones — twenty-five registers on
//! x86-64 and forty-two on AArch64, one test each. The verifier folds both
//! halves into one sixty-four-bit answer, so a poisoned vector holds the
//! pattern in both of its lanes: in one only, the equality below would hold
//! without saying which lane was read.

use super::{
    FRAME, redoubt_aegis128l_clean_frame, redoubt_aegis128l_dirty_frame,
    redoubt_aegis128l_dirty_registers, redoubt_aegis128l_frame_is_zeroized,
    redoubt_aegis128l_registers_are_zeroized,
};

const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// The byte the poison is made of, for the capture that reads a vector a byte
/// at a time rather than a word at a time.
const POISON_BYTE: u8 = 0xa5;

/// The general half of the budget, in the order the list at the top of the
/// assembly names it.
///
/// Both files have to say it, and only one of them can be the assembly: what
/// this one buys is that a register missing from the wipe is named when the
/// capture below fails, rather than reported as an index.
#[cfg(target_arch = "x86_64")]
const GENERAL: [&str; 9] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];

/// The vector half, the same way.
#[cfg(target_arch = "x86_64")]
const VECTOR: [&str; 16] = [
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
    "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
];

#[cfg(target_arch = "aarch64")]
const GENERAL: [&str; 18] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17",
];

/// v8 to v15 are absent because they are callee-saved and nothing in the
/// assembly writes one. Clearing one would mean having saved the caller's low
/// half first, which is a copy of somebody else's value on our stack.
#[cfg(target_arch = "aarch64")]
const VECTOR: [&str; 24] = [
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v16", "v17", "v18", "v19", "v20", "v21",
    "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
];

// === === === === === === === === === === ===
// Emptying the budget
// === === === === === === === === === === ===
//
// Written once because the five blocks below all need it. Copied out five
// times, a register dropped from four and kept in the fifth leaves the test
// named for it passing while its answer is about whichever other register held
// something — the failure the sweep exists to catch, inside the sweep.

/// Every vector register in the budget, emptied.
#[cfg(target_arch = "x86_64")]
macro_rules! empty_vectors {
    () => {
        concat!(
            "pxor xmm0, xmm0\n",
            "pxor xmm1, xmm1\n",
            "pxor xmm2, xmm2\n",
            "pxor xmm3, xmm3\n",
            "pxor xmm4, xmm4\n",
            "pxor xmm5, xmm5\n",
            "pxor xmm6, xmm6\n",
            "pxor xmm7, xmm7\n",
            "pxor xmm8, xmm8\n",
            "pxor xmm9, xmm9\n",
            "pxor xmm10, xmm10\n",
            "pxor xmm11, xmm11\n",
            "pxor xmm12, xmm12\n",
            "pxor xmm13, xmm13\n",
            "pxor xmm14, xmm14\n",
            "pxor xmm15, xmm15\n",
        )
    };
}

/// Every general register in the budget, emptied.
#[cfg(target_arch = "x86_64")]
macro_rules! empty_generals {
    () => {
        concat!(
            "xor rax, rax\n",
            "xor rcx, rcx\n",
            "xor rdx, rdx\n",
            "xor rsi, rsi\n",
            "xor rdi, rdi\n",
            "xor r8, r8\n",
            "xor r9, r9\n",
            "xor r10, r10\n",
            "xor r11, r11\n",
        )
    };
}

/// Every vector register in the budget, emptied.
#[cfg(target_arch = "aarch64")]
macro_rules! empty_vectors {
    () => {
        concat!(
            "movi v0.16b, #0\n",
            "movi v1.16b, #0\n",
            "movi v2.16b, #0\n",
            "movi v3.16b, #0\n",
            "movi v4.16b, #0\n",
            "movi v5.16b, #0\n",
            "movi v6.16b, #0\n",
            "movi v7.16b, #0\n",
            "movi v16.16b, #0\n",
            "movi v17.16b, #0\n",
            "movi v18.16b, #0\n",
            "movi v19.16b, #0\n",
            "movi v20.16b, #0\n",
            "movi v21.16b, #0\n",
            "movi v22.16b, #0\n",
            "movi v23.16b, #0\n",
            "movi v24.16b, #0\n",
            "movi v25.16b, #0\n",
            "movi v26.16b, #0\n",
            "movi v27.16b, #0\n",
            "movi v28.16b, #0\n",
            "movi v29.16b, #0\n",
            "movi v30.16b, #0\n",
            "movi v31.16b, #0\n",
        )
    };
}

/// Every general register in the budget, emptied.
#[cfg(target_arch = "aarch64")]
macro_rules! empty_generals {
    () => {
        concat!(
            "mov x0, xzr\n",
            "mov x1, xzr\n",
            "mov x2, xzr\n",
            "mov x3, xzr\n",
            "mov x4, xzr\n",
            "mov x5, xzr\n",
            "mov x6, xzr\n",
            "mov x7, xzr\n",
            "mov x8, xzr\n",
            "mov x9, xzr\n",
            "mov x10, xzr\n",
            "mov x11, xzr\n",
            "mov x12, xzr\n",
            "mov x13, xzr\n",
            "mov x14, xzr\n",
            "mov x15, xzr\n",
            "mov x16, xzr\n",
            "mov x17, xzr\n",
        )
    };
}

// === === === === === === === === === === ===
// redoubt_aegis128l_registers_are_zeroized
// === === === === === === === === === === ===

#[cfg(target_arch = "x86_64")]
mod dirty_register {
    use super::{POISON, redoubt_aegis128l_registers_are_zeroized};

    /// One test per general register: fill that one and nothing else, and ask.
    ///
    /// Every other test here reads a verdict the verifier gives. A verdict
    /// about a register it never actually looks at would be a clean bill of
    /// health for a register nobody checked, and there is no way to find that
    /// out except by dirtying them one at a time.
    ///
    /// The other twenty-four are emptied first, which is what makes the answer
    /// about this one. Left as the compiler happened to leave them, a verdict
    /// of "dirty" would be a verdict about whichever of them held something,
    /// and every one of these tests would pass without the register in its own
    /// name ever being looked at.
    ///
    /// The poison is an immediate and not an operand. Handed over in a
    /// register, the compiler is free to pick one of the caller-saved ones —
    /// `lateout` says they are written late, not that they are unavailable
    /// before — and the emptying above would wipe it on the way past.
    macro_rules! test_dirty_general_is_seen {
        ($name:ident, $register:tt) => {
            #[test]
            fn $name() {
                let dirty: u64;

                // SAFETY: the callee takes no argument and returns in the
                // return register, so the only registers that matter are the
                // ones named here, and every one in the budget is declared
                // clobbered.
                unsafe {
                    core::arch::asm!(
                        empty_vectors!(),
                        empty_generals!(),
                        concat!("mov ", $register, ", {poison}"),
                        "call {verifier}",
                        poison = const POISON,
                        verifier = sym redoubt_aegis128l_registers_are_zeroized,
                        lateout("rax") dirty,
                        lateout("rcx") _, lateout("rdx") _, lateout("rsi") _,
                        lateout("rdi") _, lateout("r8") _, lateout("r9") _,
                        lateout("r10") _, lateout("r11") _,
                        lateout("xmm0") _, lateout("xmm1") _, lateout("xmm2") _,
                        lateout("xmm3") _, lateout("xmm4") _, lateout("xmm5") _,
                        lateout("xmm6") _, lateout("xmm7") _, lateout("xmm8") _,
                        lateout("xmm9") _, lateout("xmm10") _, lateout("xmm11") _,
                        lateout("xmm12") _, lateout("xmm13") _, lateout("xmm14") _,
                        lateout("xmm15") _,
                    );
                }

                assert_eq!(
                    dirty, POISON,
                    concat!("a dirty ", $register, " does not reach the answer")
                );
            }
        };
    }

    /// One test per vector register: fill both of its lanes and nothing else,
    /// and ask.
    ///
    /// The pattern is built through `rax` because no immediate is that wide,
    /// and the general half is emptied afterwards rather than before, so that
    /// the scratch does not survive into the call.
    macro_rules! test_dirty_vector_is_seen {
        ($name:ident, $register:tt) => {
            #[test]
            fn $name() {
                let dirty: u64;

                // SAFETY: as above.
                unsafe {
                    core::arch::asm!(
                        empty_vectors!(),
                        "mov rax, {poison}",
                        concat!("movq ", $register, ", rax"),
                        concat!("punpcklqdq ", $register, ", ", $register),
                        empty_generals!(),
                        "call {verifier}",
                        poison = const POISON,
                        verifier = sym redoubt_aegis128l_registers_are_zeroized,
                        lateout("rax") dirty,
                        lateout("rcx") _, lateout("rdx") _, lateout("rsi") _,
                        lateout("rdi") _, lateout("r8") _, lateout("r9") _,
                        lateout("r10") _, lateout("r11") _,
                        lateout("xmm0") _, lateout("xmm1") _, lateout("xmm2") _,
                        lateout("xmm3") _, lateout("xmm4") _, lateout("xmm5") _,
                        lateout("xmm6") _, lateout("xmm7") _, lateout("xmm8") _,
                        lateout("xmm9") _, lateout("xmm10") _, lateout("xmm11") _,
                        lateout("xmm12") _, lateout("xmm13") _, lateout("xmm14") _,
                        lateout("xmm15") _,
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
    /// every test here, so one of them has to hand it a machine that is
    /// actually clean.
    #[test]
    fn test_an_empty_register_file_reads_as_empty() {
        let dirty: u64;

        // SAFETY: the callee takes no argument and returns in the return
        // register. Every register in the budget is emptied here before the
        // call and declared clobbered after it.
        unsafe {
            core::arch::asm!(
                empty_vectors!(),
                empty_generals!(),
                "call {verifier}",
                verifier = sym redoubt_aegis128l_registers_are_zeroized,
                lateout("rax") dirty,
                lateout("rcx") _, lateout("rdx") _, lateout("rsi") _,
                lateout("rdi") _, lateout("r8") _, lateout("r9") _,
                lateout("r10") _, lateout("r11") _,
                lateout("xmm0") _, lateout("xmm1") _, lateout("xmm2") _,
                lateout("xmm3") _, lateout("xmm4") _, lateout("xmm5") _,
                lateout("xmm6") _, lateout("xmm7") _, lateout("xmm8") _,
                lateout("xmm9") _, lateout("xmm10") _, lateout("xmm11") _,
                lateout("xmm12") _, lateout("xmm13") _, lateout("xmm14") _,
                lateout("xmm15") _,
            );
        }

        assert_eq!(dirty, 0, "an empty register file reads as dirty");
    }

    test_dirty_general_is_seen!(test_rax_is_seen, "rax");
    test_dirty_general_is_seen!(test_rcx_is_seen, "rcx");
    test_dirty_general_is_seen!(test_rdx_is_seen, "rdx");
    test_dirty_general_is_seen!(test_rsi_is_seen, "rsi");
    test_dirty_general_is_seen!(test_rdi_is_seen, "rdi");
    test_dirty_general_is_seen!(test_r8_is_seen, "r8");
    test_dirty_general_is_seen!(test_r9_is_seen, "r9");
    test_dirty_general_is_seen!(test_r10_is_seen, "r10");
    test_dirty_general_is_seen!(test_r11_is_seen, "r11");

    test_dirty_vector_is_seen!(test_xmm0_is_seen, "xmm0");
    test_dirty_vector_is_seen!(test_xmm1_is_seen, "xmm1");
    test_dirty_vector_is_seen!(test_xmm2_is_seen, "xmm2");
    test_dirty_vector_is_seen!(test_xmm3_is_seen, "xmm3");
    test_dirty_vector_is_seen!(test_xmm4_is_seen, "xmm4");
    test_dirty_vector_is_seen!(test_xmm5_is_seen, "xmm5");
    test_dirty_vector_is_seen!(test_xmm6_is_seen, "xmm6");
    test_dirty_vector_is_seen!(test_xmm7_is_seen, "xmm7");
    test_dirty_vector_is_seen!(test_xmm8_is_seen, "xmm8");
    test_dirty_vector_is_seen!(test_xmm9_is_seen, "xmm9");
    test_dirty_vector_is_seen!(test_xmm10_is_seen, "xmm10");
    test_dirty_vector_is_seen!(test_xmm11_is_seen, "xmm11");
    test_dirty_vector_is_seen!(test_xmm12_is_seen, "xmm12");
    test_dirty_vector_is_seen!(test_xmm13_is_seen, "xmm13");
    test_dirty_vector_is_seen!(test_xmm14_is_seen, "xmm14");
    test_dirty_vector_is_seen!(test_xmm15_is_seen, "xmm15");
}

#[cfg(target_arch = "aarch64")]
mod dirty_register {
    use super::{POISON, redoubt_aegis128l_registers_are_zeroized};

    /// One test per general register: fill that one and nothing else, and ask.
    ///
    /// Every other test here reads a verdict the verifier gives. A verdict
    /// about a register it never actually looks at would be a clean bill of
    /// health for a register nobody checked, and there is no way to find that
    /// out except by dirtying them one at a time.
    ///
    /// The other forty-one are emptied first, which is what makes the answer
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
    macro_rules! test_dirty_general_is_seen {
        ($name:ident, $register:tt) => {
            #[test]
            fn $name() {
                let dirty: u64;

                // SAFETY: the callee takes no argument and returns in the
                // return register, so the only registers that matter are the
                // ones named here, and every one in the budget is declared
                // clobbered. x30 is declared too, because `bl` writes it.
                unsafe {
                    core::arch::asm!(
                        empty_vectors!(),
                        empty_generals!(),
                        concat!("mov ", $register, ", #0xa5a5"),
                        concat!("movk ", $register, ", #0xa5a5, lsl #16"),
                        concat!("movk ", $register, ", #0xa5a5, lsl #32"),
                        concat!("movk ", $register, ", #0xa5a5, lsl #48"),
                        "bl {verifier}",
                        verifier = sym redoubt_aegis128l_registers_are_zeroized,
                        lateout("x0") dirty,
                        lateout("x1") _, lateout("x2") _, lateout("x3") _,
                        lateout("x4") _, lateout("x5") _, lateout("x6") _,
                        lateout("x7") _, lateout("x8") _, lateout("x9") _,
                        lateout("x10") _, lateout("x11") _, lateout("x12") _,
                        lateout("x13") _, lateout("x14") _, lateout("x15") _,
                        lateout("x16") _, lateout("x17") _, lateout("x30") _,
                        lateout("v0") _, lateout("v1") _, lateout("v2") _,
                        lateout("v3") _, lateout("v4") _, lateout("v5") _,
                        lateout("v6") _, lateout("v7") _, lateout("v16") _,
                        lateout("v17") _, lateout("v18") _, lateout("v19") _,
                        lateout("v20") _, lateout("v21") _, lateout("v22") _,
                        lateout("v23") _, lateout("v24") _, lateout("v25") _,
                        lateout("v26") _, lateout("v27") _, lateout("v28") _,
                        lateout("v29") _, lateout("v30") _, lateout("v31") _,
                    );
                }

                assert_eq!(
                    dirty, POISON,
                    concat!("a dirty ", $register, " does not reach the answer")
                );
            }
        };
    }

    /// One test per vector register: fill both of its lanes and nothing else,
    /// and ask.
    ///
    /// The pattern is built through `x0` because `movi` cannot express it, and
    /// the general half is emptied afterwards rather than before, so that the
    /// scratch does not survive into the call.
    macro_rules! test_dirty_vector_is_seen {
        ($name:ident, $register:tt) => {
            #[test]
            fn $name() {
                let dirty: u64;

                // SAFETY: as above.
                unsafe {
                    core::arch::asm!(
                        empty_vectors!(),
                        "mov x0, #0xa5a5",
                        "movk x0, #0xa5a5, lsl #16",
                        "movk x0, #0xa5a5, lsl #32",
                        "movk x0, #0xa5a5, lsl #48",
                        concat!("dup ", $register, ".2d, x0"),
                        empty_generals!(),
                        "bl {verifier}",
                        verifier = sym redoubt_aegis128l_registers_are_zeroized,
                        lateout("x0") dirty,
                        lateout("x1") _, lateout("x2") _, lateout("x3") _,
                        lateout("x4") _, lateout("x5") _, lateout("x6") _,
                        lateout("x7") _, lateout("x8") _, lateout("x9") _,
                        lateout("x10") _, lateout("x11") _, lateout("x12") _,
                        lateout("x13") _, lateout("x14") _, lateout("x15") _,
                        lateout("x16") _, lateout("x17") _, lateout("x30") _,
                        lateout("v0") _, lateout("v1") _, lateout("v2") _,
                        lateout("v3") _, lateout("v4") _, lateout("v5") _,
                        lateout("v6") _, lateout("v7") _, lateout("v16") _,
                        lateout("v17") _, lateout("v18") _, lateout("v19") _,
                        lateout("v20") _, lateout("v21") _, lateout("v22") _,
                        lateout("v23") _, lateout("v24") _, lateout("v25") _,
                        lateout("v26") _, lateout("v27") _, lateout("v28") _,
                        lateout("v29") _, lateout("v30") _, lateout("v31") _,
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
    /// every test here, so one of them has to hand it a machine that is
    /// actually clean.
    #[test]
    fn test_an_empty_register_file_reads_as_empty() {
        let dirty: u64;

        // SAFETY: the callee takes no argument and returns in the return
        // register. Every register in the budget is emptied here before the
        // call and declared clobbered after it.
        unsafe {
            core::arch::asm!(
                empty_vectors!(),
                empty_generals!(),
                "bl {verifier}",
                verifier = sym redoubt_aegis128l_registers_are_zeroized,
                lateout("x0") dirty,
                lateout("x1") _, lateout("x2") _, lateout("x3") _,
                lateout("x4") _, lateout("x5") _, lateout("x6") _,
                lateout("x7") _, lateout("x8") _, lateout("x9") _,
                lateout("x10") _, lateout("x11") _, lateout("x12") _,
                lateout("x13") _, lateout("x14") _, lateout("x15") _,
                lateout("x16") _, lateout("x17") _, lateout("x30") _,
                lateout("v0") _, lateout("v1") _, lateout("v2") _,
                lateout("v3") _, lateout("v4") _, lateout("v5") _,
                lateout("v6") _, lateout("v7") _, lateout("v16") _,
                lateout("v17") _, lateout("v18") _, lateout("v19") _,
                lateout("v20") _, lateout("v21") _, lateout("v22") _,
                lateout("v23") _, lateout("v24") _, lateout("v25") _,
                lateout("v26") _, lateout("v27") _, lateout("v28") _,
                lateout("v29") _, lateout("v30") _, lateout("v31") _,
            );
        }

        assert_eq!(dirty, 0, "an empty register file reads as dirty");
    }

    test_dirty_general_is_seen!(test_x0_is_seen, "x0");
    test_dirty_general_is_seen!(test_x1_is_seen, "x1");
    test_dirty_general_is_seen!(test_x2_is_seen, "x2");
    test_dirty_general_is_seen!(test_x3_is_seen, "x3");
    test_dirty_general_is_seen!(test_x4_is_seen, "x4");
    test_dirty_general_is_seen!(test_x5_is_seen, "x5");
    test_dirty_general_is_seen!(test_x6_is_seen, "x6");
    test_dirty_general_is_seen!(test_x7_is_seen, "x7");
    test_dirty_general_is_seen!(test_x8_is_seen, "x8");
    test_dirty_general_is_seen!(test_x9_is_seen, "x9");
    test_dirty_general_is_seen!(test_x10_is_seen, "x10");
    test_dirty_general_is_seen!(test_x11_is_seen, "x11");
    test_dirty_general_is_seen!(test_x12_is_seen, "x12");
    test_dirty_general_is_seen!(test_x13_is_seen, "x13");
    test_dirty_general_is_seen!(test_x14_is_seen, "x14");
    test_dirty_general_is_seen!(test_x15_is_seen, "x15");
    test_dirty_general_is_seen!(test_x16_is_seen, "x16");
    test_dirty_general_is_seen!(test_x17_is_seen, "x17");

    test_dirty_vector_is_seen!(test_v0_is_seen, "v0");
    test_dirty_vector_is_seen!(test_v1_is_seen, "v1");
    test_dirty_vector_is_seen!(test_v2_is_seen, "v2");
    test_dirty_vector_is_seen!(test_v3_is_seen, "v3");
    test_dirty_vector_is_seen!(test_v4_is_seen, "v4");
    test_dirty_vector_is_seen!(test_v5_is_seen, "v5");
    test_dirty_vector_is_seen!(test_v6_is_seen, "v6");
    test_dirty_vector_is_seen!(test_v7_is_seen, "v7");
    test_dirty_vector_is_seen!(test_v16_is_seen, "v16");
    test_dirty_vector_is_seen!(test_v17_is_seen, "v17");
    test_dirty_vector_is_seen!(test_v18_is_seen, "v18");
    test_dirty_vector_is_seen!(test_v19_is_seen, "v19");
    test_dirty_vector_is_seen!(test_v20_is_seen, "v20");
    test_dirty_vector_is_seen!(test_v21_is_seen, "v21");
    test_dirty_vector_is_seen!(test_v22_is_seen, "v22");
    test_dirty_vector_is_seen!(test_v23_is_seen, "v23");
    test_dirty_vector_is_seen!(test_v24_is_seen, "v24");
    test_dirty_vector_is_seen!(test_v25_is_seen, "v25");
    test_dirty_vector_is_seen!(test_v26_is_seen, "v26");
    test_dirty_vector_is_seen!(test_v27_is_seen, "v27");
    test_dirty_vector_is_seen!(test_v28_is_seen, "v28");
    test_dirty_vector_is_seen!(test_v29_is_seen, "v29");
    test_dirty_vector_is_seen!(test_v30_is_seen, "v30");
    test_dirty_vector_is_seen!(test_v31_is_seen, "v31");
}

// === === === === === === === === === === ===
// redoubt_aegis128l_frame_is_zeroized
// === === === === === === === === === === ===

/// One call per byte: leave that one and nothing else, and ask.
///
/// Every routine reads a verdict this gives, and a verdict about a byte it
/// never looks at would be a clean bill of health for memory nobody inspected.
/// Thirty-two calls are cheap and they are the only way to know it reads all of
/// them — an off-by-one at either end, against the return address sitting next
/// door, shows up here and nowhere else.
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
            redoubt_aegis128l_dirty_frame(at);
            redoubt_aegis128l_frame_is_zeroized()
        };

        assert_ne!(dirty, 0, "byte {at} of the frame reads as empty");
    }
}

/// The other way round, and the reason the sweep above means anything.
///
/// A verifier that answered "dirty" whatever it was handed would pass every
/// one of those thirty-two.
#[test]
fn test_a_frame_written_and_emptied_reads_as_empty() {
    // SAFETY: the target fills the frame it allocated and empties it again,
    // and the verifier reads what it released.
    let dirty = unsafe {
        redoubt_aegis128l_clean_frame();
        redoubt_aegis128l_frame_is_zeroized()
    };

    // Assert zeroization!
    assert_eq!(dirty, 0, "a frame that was emptied reads as full");
}

// === === === === === === === === === === ===
// redoubt_aegis128l_dirty_registers
// === === === === === === === === === === ===

/// The writer must fill every general register in the budget.
///
/// The sweep above establishes that the verifier sees any one register. This is
/// the other half of that instrument: the negatives in `asm` read "something is
/// still full", and a writer short by one register would let them pass while
/// never dirtying the register the routine under test failed to wipe.
///
/// Capture the registers directly rather than asking the OR verifier, for the
/// same reason the frame writer is captured below: an OR cannot tell which of
/// them carried the answer. They are emptied first, so an equality here can
/// only have come from the writer.
///
/// The two halves are separate tests because they are separate claims, and
/// because a failure should name a register rather than a position in a list
/// that holds both kinds.
#[test]
fn test_dirty_registers_fills_every_general_register_in_the_budget() {
    let mut actual = [0u64; GENERAL.len()];

    #[cfg(target_arch = "x86_64")]
    // SAFETY: the callee takes no argument, and r12 is outside the budget it
    // fills, so the destination survives the call. `actual` is as long as the
    // general half of the budget, and the stores below cover it exactly once
    // each.
    unsafe {
        core::arch::asm!(
            empty_vectors!(),
            empty_generals!(),
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
            writer = sym redoubt_aegis128l_dirty_registers,
            inlateout("r12") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: the same, with x20 outside the budget instead of r12.
    unsafe {
        core::arch::asm!(
            empty_vectors!(),
            empty_generals!(),
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
            writer = sym redoubt_aegis128l_dirty_registers,
            inlateout("x20") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(
            value, POISON,
            "{} came back from the writer empty",
            GENERAL[at]
        );
    }
}

/// The writer must fill every vector register in the budget, in both lanes.
///
/// Both lanes, because the verifier folds them together: a writer that filled
/// only the low half of each would still make every negative in `asm` read
/// "something is still full", while a routine that wiped only the low half
/// would go unnoticed.
#[test]
fn test_dirty_registers_fills_every_vector_register_in_the_budget() {
    let mut actual = [[0u8; 16]; VECTOR.len()];

    #[cfg(target_arch = "x86_64")]
    // SAFETY: the callee takes no argument, and r12 is outside the budget it
    // fills, so the destination survives the call. `actual` is sixteen bytes
    // per vector register, and the stores below cover it exactly once each.
    unsafe {
        core::arch::asm!(
            empty_vectors!(),
            empty_generals!(),
            "call {writer}",
            "movdqu [r12], xmm0",
            "movdqu [r12 + 16], xmm1",
            "movdqu [r12 + 32], xmm2",
            "movdqu [r12 + 48], xmm3",
            "movdqu [r12 + 64], xmm4",
            "movdqu [r12 + 80], xmm5",
            "movdqu [r12 + 96], xmm6",
            "movdqu [r12 + 112], xmm7",
            "movdqu [r12 + 128], xmm8",
            "movdqu [r12 + 144], xmm9",
            "movdqu [r12 + 160], xmm10",
            "movdqu [r12 + 176], xmm11",
            "movdqu [r12 + 192], xmm12",
            "movdqu [r12 + 208], xmm13",
            "movdqu [r12 + 224], xmm14",
            "movdqu [r12 + 240], xmm15",
            writer = sym redoubt_aegis128l_dirty_registers,
            inlateout("r12") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: the same, with x20 outside the budget instead of r12.
    unsafe {
        core::arch::asm!(
            empty_vectors!(),
            empty_generals!(),
            "bl {writer}",
            "stp q0, q1, [x20]",
            "stp q2, q3, [x20, #32]",
            "stp q4, q5, [x20, #64]",
            "stp q6, q7, [x20, #96]",
            "stp q16, q17, [x20, #128]",
            "stp q18, q19, [x20, #160]",
            "stp q20, q21, [x20, #192]",
            "stp q22, q23, [x20, #224]",
            "stp q24, q25, [x20, #256]",
            "stp q26, q27, [x20, #288]",
            "stp q28, q29, [x20, #320]",
            "stp q30, q31, [x20, #352]",
            writer = sym redoubt_aegis128l_dirty_registers,
            inlateout("x20") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    for (at, value) in actual.iter().enumerate() {
        assert_eq!(
            value, &[POISON_BYTE; 16],
            "{} came back from the writer with a lane empty",
            VECTOR[at]
        );
    }
}

// === === === === === === === === === === ===
// redoubt_aegis128l_dirty_frame
// === === === === === === === === === === ===

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
        // SAFETY: at is inside the writer's frame, and actual covers all
        // thirty-two captured bytes. r12 holds its pointer across the call;
        // the writer preserves it. The reservation keeps call alignment and
        // includes eight bytes below the frame plus the return-address slot:
        // the writer's frame is [rsp + 8, rsp + 8 + FRAME) after reserving
        // again.
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
                writer = sym redoubt_aegis128l_dirty_frame,
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
                writer = sym redoubt_aegis128l_dirty_frame,
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
