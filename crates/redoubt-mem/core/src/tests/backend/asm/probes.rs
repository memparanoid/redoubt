// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each routine in the assembly leaves in the registers, and whether the
//! verifier that answers that reads all of them. No routine takes a frame, so
//! nothing here measures one.

use std::vec::Vec;

use rstest::rstest;

unsafe extern "C" {
    fn redoubt_mem_copy_nonoverlapping(src: *const u8, dst: *mut u8, bytes: usize);
    fn redoubt_mem_swap_nonoverlapping(a: *mut u8, b: *mut u8, bytes: usize);
    fn redoubt_mem_is_utf8(bytes: *const u8, len: usize, answer: *mut u8);
    fn redoubt_mem_is_zeroized(bytes: *const u8, len: usize, answer: *mut u8);

    fn redoubt_mem_registers_are_zeroized() -> u64;
    fn redoubt_mem_dirty_registers();
    fn redoubt_mem_dirty_vector_low();
    fn redoubt_mem_dirty_vector_high();
}

/// What the register writer leaves in every register of the budget.
const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// What a register holds before a writer is captured, so that a zero the
/// capture finds is one the writer put there.
const STALE: u64 = 0x3c3c_3c3c_3c3c_3c3c;

// ============================================================================
// What differs between the targets
// ============================================================================

/// The budget as the assembly lists it, so that a failure names the register
/// rather than an index.
#[cfg(target_arch = "x86_64")]
const GENERAL: [&str; 9] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];

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

#[cfg(target_arch = "aarch64")]
const VECTOR: [&str; 24] = [
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v16", "v17", "v18", "v19", "v20", "v21",
    "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
];

/// One line per register: a loop needs a counter, and the counter would be one
/// of the registers being emptied.
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

/// One register filled, every other one emptied, and the verifier asked.
///
/// The others are emptied so the answer can only come from the register the
/// test names. The poison is an immediate and not an operand: in a register,
/// the compiler may pick a caller-saved one and the emptying wipes it.
#[cfg(target_arch = "x86_64")]
macro_rules! test_dirty_general_is_seen {
    ($name:ident, $register:tt) => {
        #[test]
        fn $name() {
            let dirty: u64;

            // SAFETY: the verifier takes no argument and answers in rax, and
            // every caller-saved register is declared clobbered.
            unsafe {
                core::arch::asm!(
                    empty_vectors!(),
                    empty_generals!(),
                    concat!("mov ", $register, ", {poison}"),
                    "call {verifier}",
                    poison = const POISON,
                    verifier = sym redoubt_mem_registers_are_zeroized,
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

/// One half of one vector register filled, everything else emptied, and the
/// verifier asked: a test for each half, since the verifier folds the high one
/// down to the width of its answer and a fold that dropped it would still see
/// the low one.
///
/// The pattern goes through rax because no immediate is that wide, and the
/// general registers are emptied after it so the scratch does not reach the
/// call.
#[cfg(target_arch = "x86_64")]
macro_rules! test_dirty_vector_is_seen {
    ($low:ident, $high:ident, $register:tt) => {
        test_dirty_vector_is_seen!(@half $low, $register, "", " low");
        test_dirty_vector_is_seen!(@half $high, $register,
                                   concat!("pslldq ", $register, ", 8"), " high");
    };
    (@half $name:ident, $register:tt, $shift:expr, $half:literal) => {
        #[test]
        fn $name() {
            let dirty: u64;

            // SAFETY: the verifier takes no argument and answers in rax, and
            // every caller-saved register is declared clobbered.
            unsafe {
                core::arch::asm!(
                    empty_vectors!(),
                    "mov rax, {poison}",
                    concat!("movq ", $register, ", rax"),
                    $shift,
                    empty_generals!(),
                    "call {verifier}",
                    poison = const POISON,
                    verifier = sym redoubt_mem_registers_are_zeroized,
                    lateout("rax") dirty,
                    clobber_abi("C"),
                );
            }

            assert_eq!(
                dirty, POISON,
                concat!("a dirty", $half, " half of ", $register, " does not reach the answer")
            );
        }
    };
}

/// One register filled, every other one emptied, and the verifier asked.
///
/// The others are emptied so the answer can only come from the register the
/// test names. The poison is built in place a quarter at a time and not handed
/// over: in a register, the compiler may pick a caller-saved one and the
/// emptying wipes it.
#[cfg(target_arch = "aarch64")]
macro_rules! test_dirty_general_is_seen {
    ($name:ident, $register:tt) => {
        #[test]
        fn $name() {
            let dirty: u64;

            // SAFETY: the verifier takes no argument and answers in x0, and
            // every caller-saved register is declared clobbered.
            unsafe {
                core::arch::asm!(
                    empty_vectors!(),
                    empty_generals!(),
                    concat!("movz ", $register, ", #0xa5a5"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #16"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #32"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #48"),
                    "bl {verifier}",
                    verifier = sym redoubt_mem_registers_are_zeroized,
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

/// One lane of one vector register filled, everything else emptied, and the
/// verifier asked: a test for each lane, since the verifier folds the high one
/// down to the width of its answer and a fold that dropped it would still see
/// the low one.
///
/// The pattern goes through x0 because `movi` cannot express it, and the
/// general registers are emptied after it so the scratch does not reach the
/// call.
#[cfg(target_arch = "aarch64")]
macro_rules! test_dirty_vector_is_seen {
    ($low:ident, $high:ident, $register:tt) => {
        test_dirty_vector_is_seen!(@lane $low, $register, "0", " low");
        test_dirty_vector_is_seen!(@lane $high, $register, "1", " high");
    };
    (@lane $name:ident, $register:tt, $lane:literal, $half:literal) => {
        #[test]
        fn $name() {
            let dirty: u64;

            // SAFETY: the verifier takes no argument and answers in x0, and
            // every caller-saved register is declared clobbered.
            unsafe {
                core::arch::asm!(
                    empty_vectors!(),
                    "movz x0, #0xa5a5",
                    "movk x0, #0xa5a5, lsl #16",
                    "movk x0, #0xa5a5, lsl #32",
                    "movk x0, #0xa5a5, lsl #48",
                    concat!("mov ", $register, ".d[", $lane, "], x0"),
                    empty_generals!(),
                    "bl {verifier}",
                    verifier = sym redoubt_mem_registers_are_zeroized,
                    lateout("x0") dirty,
                    clobber_abi("C"),
                );
            }

            assert_eq!(
                dirty, POISON,
                concat!("a dirty", $half, " lane of ", $register, " does not reach the answer")
            );
        }
    };
}

/// A test per entry of `GENERAL` and `VECTOR`, written by hand, and how many
/// there are.
#[cfg(target_arch = "x86_64")]
macro_rules! every_register {
    () => {
        test_dirty_general_is_seen!(test_rax_is_seen, "rax");
        test_dirty_general_is_seen!(test_rcx_is_seen, "rcx");
        test_dirty_general_is_seen!(test_rdx_is_seen, "rdx");
        test_dirty_general_is_seen!(test_rsi_is_seen, "rsi");
        test_dirty_general_is_seen!(test_rdi_is_seen, "rdi");
        test_dirty_general_is_seen!(test_r8_is_seen, "r8");
        test_dirty_general_is_seen!(test_r9_is_seen, "r9");
        test_dirty_general_is_seen!(test_r10_is_seen, "r10");
        test_dirty_general_is_seen!(test_r11_is_seen, "r11");

        test_dirty_vector_is_seen!(test_xmm0_low_is_seen, test_xmm0_high_is_seen, "xmm0");
        test_dirty_vector_is_seen!(test_xmm1_low_is_seen, test_xmm1_high_is_seen, "xmm1");
        test_dirty_vector_is_seen!(test_xmm2_low_is_seen, test_xmm2_high_is_seen, "xmm2");
        test_dirty_vector_is_seen!(test_xmm3_low_is_seen, test_xmm3_high_is_seen, "xmm3");
        test_dirty_vector_is_seen!(test_xmm4_low_is_seen, test_xmm4_high_is_seen, "xmm4");
        test_dirty_vector_is_seen!(test_xmm5_low_is_seen, test_xmm5_high_is_seen, "xmm5");
        test_dirty_vector_is_seen!(test_xmm6_low_is_seen, test_xmm6_high_is_seen, "xmm6");
        test_dirty_vector_is_seen!(test_xmm7_low_is_seen, test_xmm7_high_is_seen, "xmm7");
        test_dirty_vector_is_seen!(test_xmm8_low_is_seen, test_xmm8_high_is_seen, "xmm8");
        test_dirty_vector_is_seen!(test_xmm9_low_is_seen, test_xmm9_high_is_seen, "xmm9");
        test_dirty_vector_is_seen!(test_xmm10_low_is_seen, test_xmm10_high_is_seen, "xmm10");
        test_dirty_vector_is_seen!(test_xmm11_low_is_seen, test_xmm11_high_is_seen, "xmm11");
        test_dirty_vector_is_seen!(test_xmm12_low_is_seen, test_xmm12_high_is_seen, "xmm12");
        test_dirty_vector_is_seen!(test_xmm13_low_is_seen, test_xmm13_high_is_seen, "xmm13");
        test_dirty_vector_is_seen!(test_xmm14_low_is_seen, test_xmm14_high_is_seen, "xmm14");
        test_dirty_vector_is_seen!(test_xmm15_low_is_seen, test_xmm15_high_is_seen, "xmm15");

        pub(super) const GENERAL_TESTS: usize = 9;
        pub(super) const VECTOR_TESTS: usize = 16;
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! every_register {
    () => {
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

        test_dirty_vector_is_seen!(test_v0_low_is_seen, test_v0_high_is_seen, "v0");
        test_dirty_vector_is_seen!(test_v1_low_is_seen, test_v1_high_is_seen, "v1");
        test_dirty_vector_is_seen!(test_v2_low_is_seen, test_v2_high_is_seen, "v2");
        test_dirty_vector_is_seen!(test_v3_low_is_seen, test_v3_high_is_seen, "v3");
        test_dirty_vector_is_seen!(test_v4_low_is_seen, test_v4_high_is_seen, "v4");
        test_dirty_vector_is_seen!(test_v5_low_is_seen, test_v5_high_is_seen, "v5");
        test_dirty_vector_is_seen!(test_v6_low_is_seen, test_v6_high_is_seen, "v6");
        test_dirty_vector_is_seen!(test_v7_low_is_seen, test_v7_high_is_seen, "v7");
        test_dirty_vector_is_seen!(test_v16_low_is_seen, test_v16_high_is_seen, "v16");
        test_dirty_vector_is_seen!(test_v17_low_is_seen, test_v17_high_is_seen, "v17");
        test_dirty_vector_is_seen!(test_v18_low_is_seen, test_v18_high_is_seen, "v18");
        test_dirty_vector_is_seen!(test_v19_low_is_seen, test_v19_high_is_seen, "v19");
        test_dirty_vector_is_seen!(test_v20_low_is_seen, test_v20_high_is_seen, "v20");
        test_dirty_vector_is_seen!(test_v21_low_is_seen, test_v21_high_is_seen, "v21");
        test_dirty_vector_is_seen!(test_v22_low_is_seen, test_v22_high_is_seen, "v22");
        test_dirty_vector_is_seen!(test_v23_low_is_seen, test_v23_high_is_seen, "v23");
        test_dirty_vector_is_seen!(test_v24_low_is_seen, test_v24_high_is_seen, "v24");
        test_dirty_vector_is_seen!(test_v25_low_is_seen, test_v25_high_is_seen, "v25");
        test_dirty_vector_is_seen!(test_v26_low_is_seen, test_v26_high_is_seen, "v26");
        test_dirty_vector_is_seen!(test_v27_low_is_seen, test_v27_high_is_seen, "v27");
        test_dirty_vector_is_seen!(test_v28_low_is_seen, test_v28_high_is_seen, "v28");
        test_dirty_vector_is_seen!(test_v29_low_is_seen, test_v29_high_is_seen, "v29");
        test_dirty_vector_is_seen!(test_v30_low_is_seen, test_v30_high_is_seen, "v30");
        test_dirty_vector_is_seen!(test_v31_low_is_seen, test_v31_high_is_seen, "v31");

        pub(super) const GENERAL_TESTS: usize = 18;
        pub(super) const VECTOR_TESTS: usize = 24;
    };
}

#[cfg(target_arch = "x86_64")]
fn read_an_empty_register_file() -> u64 {
    let dirty: u64;

    // SAFETY: the verifier takes no argument and answers in rax, and every
    // caller-saved register is declared clobbered.
    unsafe {
        core::arch::asm!(
            empty_vectors!(),
            empty_generals!(),
            "call {verifier}",
            verifier = sym redoubt_mem_registers_are_zeroized,
            lateout("rax") dirty,
            clobber_abi("C"),
        );
    }

    dirty
}

#[cfg(target_arch = "aarch64")]
fn read_an_empty_register_file() -> u64 {
    let dirty: u64;

    // SAFETY: the verifier takes no argument and answers in x0, and every
    // caller-saved register is declared clobbered.
    unsafe {
        core::arch::asm!(
            empty_vectors!(),
            empty_generals!(),
            "bl {verifier}",
            verifier = sym redoubt_mem_registers_are_zeroized,
            lateout("x0") dirty,
            clobber_abi("C"),
        );
    }

    dirty
}

/// Every general register of the budget as a register writer leaves it, stored
/// rather than asked: the verifier answers with an OR, and an OR cannot say
/// which register carried it. The registers hold `STALE` going in.
#[cfg(target_arch = "x86_64")]
macro_rules! capture_the_general_writer {
    ($writer:path) => {{
        let mut actual = [0_u64; GENERAL.len()];

        // SAFETY: the writer takes no argument and leaves r12 alone, which
        // holds the destination across the call. `actual` is one word per
        // register, and the stores cover it once each.
        unsafe {
            core::arch::asm!(
                empty_vectors!(),
                "mov rax, {poison}",
                "mov rcx, rax",
                "mov rdx, rax",
                "mov rsi, rax",
                "mov rdi, rax",
                "mov r8, rax",
                "mov r9, rax",
                "mov r10, rax",
                "mov r11, rax",
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
                poison = const STALE,
                writer = sym $writer,
                inlateout("r12") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        actual
    }};
}

/// Every general register of the budget as a register writer leaves it, stored
/// rather than asked: the verifier answers with an OR, and an OR cannot say
/// which register carried it. The registers hold `STALE` going in.
#[cfg(target_arch = "aarch64")]
macro_rules! capture_the_general_writer {
    ($writer:path) => {{
        let mut actual = [0_u64; GENERAL.len()];

        // SAFETY: the writer takes no argument and leaves x20 alone, which
        // holds the destination across the call. `actual` is one word per
        // register, and the stores cover it once each.
        unsafe {
            core::arch::asm!(
                empty_vectors!(),
                "movz x0, #0x3c3c",
                "movk x0, #0x3c3c, lsl #16",
                "movk x0, #0x3c3c, lsl #32",
                "movk x0, #0x3c3c, lsl #48",
                "mov x1, x0",
                "mov x2, x0",
                "mov x3, x0",
                "mov x4, x0",
                "mov x5, x0",
                "mov x6, x0",
                "mov x7, x0",
                "mov x8, x0",
                "mov x9, x0",
                "mov x10, x0",
                "mov x11, x0",
                "mov x12, x0",
                "mov x13, x0",
                "mov x14, x0",
                "mov x15, x0",
                "mov x16, x0",
                "mov x17, x0",
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
                writer = sym $writer,
                inlateout("x20") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        actual
    }};
}

/// Every vector register of the budget as a register writer leaves it, half by
/// half, so a half written or left wrong is named. The registers hold `STALE`
/// in both halves going in.
#[cfg(target_arch = "x86_64")]
macro_rules! capture_the_vector_writer {
    ($writer:path) => {{
        let mut actual = [[0_u64; 2]; VECTOR.len()];

        // SAFETY: the writer takes no argument and leaves r12 alone, which
        // holds the destination across the call. `actual` is two words per
        // register, and the stores cover it once each.
        unsafe {
            core::arch::asm!(
                empty_generals!(),
                "mov rax, {poison}",
                "movq xmm0, rax",
                "punpcklqdq xmm0, xmm0",
                "movdqa xmm1, xmm0",
                "movdqa xmm2, xmm0",
                "movdqa xmm3, xmm0",
                "movdqa xmm4, xmm0",
                "movdqa xmm5, xmm0",
                "movdqa xmm6, xmm0",
                "movdqa xmm7, xmm0",
                "movdqa xmm8, xmm0",
                "movdqa xmm9, xmm0",
                "movdqa xmm10, xmm0",
                "movdqa xmm11, xmm0",
                "movdqa xmm12, xmm0",
                "movdqa xmm13, xmm0",
                "movdqa xmm14, xmm0",
                "movdqa xmm15, xmm0",
                "xor eax, eax",
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
                poison = const STALE,
                writer = sym $writer,
                inlateout("r12") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        actual
    }};
}

/// Every vector register of the budget as a register writer leaves it, lane by
/// lane, so a lane written or left wrong is named. The registers hold `STALE`
/// in both lanes going in.
#[cfg(target_arch = "aarch64")]
macro_rules! capture_the_vector_writer {
    ($writer:path) => {{
        let mut actual = [[0_u64; 2]; VECTOR.len()];

        // SAFETY: the writer takes no argument and leaves x20 alone, which
        // holds the destination across the call. `actual` is two words per
        // register, and the stores cover it once each.
        unsafe {
            core::arch::asm!(
                "movz x0, #0x3c3c",
                "movk x0, #0x3c3c, lsl #16",
                "movk x0, #0x3c3c, lsl #32",
                "movk x0, #0x3c3c, lsl #48",
                "dup v0.2d, x0",
                "mov v1.16b, v0.16b",
                "mov v2.16b, v0.16b",
                "mov v3.16b, v0.16b",
                "mov v4.16b, v0.16b",
                "mov v5.16b, v0.16b",
                "mov v6.16b, v0.16b",
                "mov v7.16b, v0.16b",
                "mov v16.16b, v0.16b",
                "mov v17.16b, v0.16b",
                "mov v18.16b, v0.16b",
                "mov v19.16b, v0.16b",
                "mov v20.16b, v0.16b",
                "mov v21.16b, v0.16b",
                "mov v22.16b, v0.16b",
                "mov v23.16b, v0.16b",
                "mov v24.16b, v0.16b",
                "mov v25.16b, v0.16b",
                "mov v26.16b, v0.16b",
                "mov v27.16b, v0.16b",
                "mov v28.16b, v0.16b",
                "mov v29.16b, v0.16b",
                "mov v30.16b, v0.16b",
                "mov v31.16b, v0.16b",
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
                writer = sym $writer,
                inlateout("x20") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        actual
    }};
}

#[cfg(target_arch = "x86_64")]
macro_rules! tail_branch {
    () => {
        "jmp {target}"
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! tail_branch {
    () => {
        "b {target}"
    };
}

/// The routine through a pointer, then the verifier, in one block: nothing Rust
/// emits runs between them.
#[cfg(target_arch = "x86_64")]
macro_rules! measure {
    ($routine:expr, $a0:expr, $a1:expr, $a2:expr $(,)?) => {{
        let registers: u64;

        core::arch::asm!(
            "call r11",
            "call {register_probe}",
            register_probe = sym redoubt_mem_registers_are_zeroized,
            inlateout("r11") $routine => _,
            inlateout("rdi") $a0 => _,
            inlateout("rsi") $a1 => _,
            inlateout("rdx") $a2 => _,
            lateout("rax") registers,
            clobber_abi("C"),
        );

        registers
    }};
}

/// The routine through a pointer, then the verifier, in one block: nothing Rust
/// emits runs between them.
#[cfg(target_arch = "aarch64")]
macro_rules! measure {
    ($routine:expr, $a0:expr, $a1:expr, $a2:expr $(,)?) => {{
        let registers: u64;

        core::arch::asm!(
            "blr x16",
            "bl {register_probe}",
            register_probe = sym redoubt_mem_registers_are_zeroized,
            inlateout("x16") $routine => _,
            inlateout("x0") $a0 => registers,
            inlateout("x1") $a1 => _,
            inlateout("x2") $a2 => _,
            clobber_abi("C"),
        );

        registers
    }};
}

/// Stand-ins for a routine, with its arguments and none of its work.
///
/// Naked and a tail branch, so no prologue of their own touches a register the
/// writer filled. The one that does nothing measures the gap:
/// without it, a clean reading of the real routine could be the call site
/// having tidied up.
macro_rules! controls {
    ([$registers:ident, $low:ident, $high:ident, $untouched:ident], ($($kind:ty),*)) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $untouched($(_: $kind),*) {
            core::arch::naked_asm!("ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $registers($(_: $kind),*) {
            core::arch::naked_asm!(
                tail_branch!(),
                target = sym redoubt_mem_dirty_registers,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $low($(_: $kind),*) {
            core::arch::naked_asm!(
                tail_branch!(),
                target = sym redoubt_mem_dirty_vector_low,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $high($(_: $kind),*) {
            core::arch::naked_asm!(
                tail_branch!(),
                target = sym redoubt_mem_dirty_vector_high,
            );
        }
    };
}

/// Which residue a case deliberately leaves, or `Nothing` for the routine.
#[derive(Clone, Copy)]
enum Left {
    Registers,
    VectorLows,
    VectorHighs,
    Everything,
    Nothing,
}

/// Each negative asks only about the residue it leaves. A half left full is
/// asserted exactly: every other bit of the budget is empty, so `POISON` can
/// only come through that half.
fn assert_residue(registers: u64, left: Left) {
    match left {
        Left::Registers => {
            assert_ne!(
                registers, 0,
                "registers the replacement left full read as empty"
            );
        }
        Left::VectorLows => {
            assert_eq!(
                registers, POISON,
                "the low halves the replacement left full do not reach the answer"
            );
        }
        Left::VectorHighs => {
            assert_eq!(
                registers, POISON,
                "the high halves the replacement left full do not reach the answer"
            );
        }
        Left::Everything => {
            assert_ne!(
                registers, 0,
                "a call that ran nothing emptied the registers"
            );
        }
        Left::Nothing => {
            // Assert zeroization!
            assert_eq!(registers, 0, "the registers after the real routine");
        }
    }
}

/// The stand-ins for a routine and its cases, the negatives first.
///
/// `$setup` binds what the arguments name, and the routine is measured once per
/// value the `for` walks.
macro_rules! test_what_the_routine_leaves {
    (
        $name:ident, $real:path, fn($($kind:ty),*),
        [$registers:ident, $low:ident, $high:ident, $untouched:ident],
        for $each:ident in $over:expr,
        { $($setup:tt)* },
        ($($argument:expr),*)
    ) => {
        controls!([$registers, $low, $high, $untouched], ($($kind),*));

        #[rstest]
        #[case::registers_left_full($registers as unsafe extern "C" fn($($kind),*), Left::Registers)]
        #[case::low_left_full($low as unsafe extern "C" fn($($kind),*), Left::VectorLows)]
        #[case::high_left_full($high as unsafe extern "C" fn($($kind),*), Left::VectorHighs)]
        #[case::nothing_ran($untouched as unsafe extern "C" fn($($kind),*), Left::Everything)]
        #[case::real($real as unsafe extern "C" fn($($kind),*), Left::Nothing)]
        fn $name(#[case] routine: unsafe extern "C" fn($($kind),*), #[case] left: Left) {
            let routine = core::hint::black_box(routine);

            for $each in $over {
                // CORRECTNESS: the arguments are settled before the writer
                // runs. Anything computed after it runs in the registers it
                // just filled.
                $($setup)*

                // SAFETY: every pointer the setup binds is to storage of the
                // width the routine reads or writes, and none of them overlap.
                let registers = unsafe {
                    redoubt_mem_dirty_registers();
                    measure!(routine, $($argument),*)
                };

                assert_residue(registers, left);
            }
        }
    };
}

// ============================================================================
// redoubt_mem_registers_are_zeroized
// ============================================================================

/// A verifier that answered "dirty" whatever it was handed would pass every
/// test that fills a register.
#[test]
fn test_an_empty_register_file_reads_as_empty() {
    assert_eq!(
        read_an_empty_register_file(),
        0,
        "an empty register file reads as dirty"
    );
}

mod every_register {
    use super::{POISON, redoubt_mem_registers_are_zeroized};

    every_register!();
}

/// A register in a list and missing from the tests is reported filled by the
/// capture while the verifier is never asked about it.
#[test]
fn test_the_lists_name_as_many_registers_as_there_are_tests() {
    assert_eq!(GENERAL.len(), every_register::GENERAL_TESTS);
    assert_eq!(VECTOR.len(), every_register::VECTOR_TESTS);
}

// ============================================================================
// redoubt_mem_dirty_registers
// ============================================================================

/// A writer short by one register would let every negative below pass while
/// never dirtying the register the routine failed to wipe.
#[test]
fn test_dirty_registers_fills_every_general_register_in_the_budget() {
    let actual = capture_the_general_writer!(redoubt_mem_dirty_registers);

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(
            value, POISON,
            "{} came back from the writer empty",
            GENERAL[at]
        );
    }
}

/// Both lanes: the verifier folds them together, so a writer that filled one
/// would hide a routine that wiped only that one.
#[test]
fn test_dirty_registers_fills_every_vector_register_in_the_budget() {
    let actual = capture_the_vector_writer!(redoubt_mem_dirty_registers);

    for (at, halves) in actual.iter().enumerate() {
        assert_eq!(
            halves,
            &[POISON, POISON],
            "{} came back from the writer with a half empty",
            VECTOR[at]
        );
    }
}

// ============================================================================
// redoubt_mem_dirty_vector_low
// ============================================================================

#[test]
fn test_dirty_vector_low_empties_every_general_register_in_the_budget() {
    let actual = capture_the_general_writer!(redoubt_mem_dirty_vector_low);

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(value, 0, "{} came back from the writer full", GENERAL[at]);
    }
}

#[test]
fn test_dirty_vector_low_fills_only_the_low_half_of_every_vector_register() {
    let actual = capture_the_vector_writer!(redoubt_mem_dirty_vector_low);

    for (at, halves) in actual.iter().enumerate() {
        assert_eq!(
            halves,
            &[POISON, 0],
            "{} did not come back with only its low half full",
            VECTOR[at]
        );
    }
}

// ============================================================================
// redoubt_mem_dirty_vector_high
// ============================================================================

#[test]
fn test_dirty_vector_high_empties_every_general_register_in_the_budget() {
    let actual = capture_the_general_writer!(redoubt_mem_dirty_vector_high);

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(value, 0, "{} came back from the writer full", GENERAL[at]);
    }
}

#[test]
fn test_dirty_vector_high_fills_only_the_high_half_of_every_vector_register() {
    let actual = capture_the_vector_writer!(redoubt_mem_dirty_vector_high);

    for (at, halves) in actual.iter().enumerate() {
        assert_eq!(
            halves,
            &[0, POISON],
            "{} did not come back with only its high half full",
            VECTOR[at]
        );
    }
}

// ============================================================================
// What the routines leave
// ============================================================================

/// Each side of every length at which the copy or the swap changes path, on
/// either target.
const LENGTHS: [usize; 23] = [
    0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 96, 511, 512, 513, 1024, 4096,
];

/// `length` bytes, none of them zero: a zero byte left in a register reads as
/// emptied.
fn said(length: usize) -> Vec<u8> {
    (0..length).map(|at| ((at as u8) ^ 0x5a) | 1).collect()
}

/// Every branch of the UTF-8 check: each width accepted, each bound on a second
/// byte, and each way to be refused.
const TEXTS: [&[u8]; 23] = [
    b"",
    b"a",
    "\u{e9}".as_bytes(),
    "\u{20ac}".as_bytes(),
    "\u{1f600}".as_bytes(),
    &[0xE0, 0xA0, 0x80],
    &[0xED, 0x9F, 0xBF],
    &[0xF0, 0x90, 0x80, 0x80],
    &[0xF4, 0x8F, 0xBF, 0xBF],
    &[0x80],
    &[0xC0, 0x80],
    &[0xF5],
    &[0xC3],
    &[0xC3, 0x28],
    &[0xE2, 0x82],
    &[0xE0, 0x80, 0x80],
    &[0xED, 0xA0, 0x80],
    &[0xE2, 0x82, 0x28],
    &[0xF0, 0x9F, 0x98],
    &[0xF0, 0x80, 0x80, 0x80],
    &[0xF4, 0x90, 0x80, 0x80],
    &[0xF0, 0x9F, 0x28, 0x80],
    &[0xF0, 0x9F, 0x98, 0x28],
];

// ============================================================================
// redoubt_mem_copy_nonoverlapping
// ============================================================================

test_what_the_routine_leaves!(
    test_copy_nonoverlapping_leaves_the_residue_its_case_declares,
    redoubt_mem_copy_nonoverlapping,
    fn(*const u8, *mut u8, usize),
    [dirty_copy_registers, dirty_copy_low, dirty_copy_high, untouched_copy],
    for bytes in LENGTHS,
    {
        let from = said(bytes);
        let mut into = std::vec![0_u8; bytes];
        let src = from.as_ptr();
        let dst = into.as_mut_ptr();
    },
    (src, dst, bytes)
);

// ============================================================================
// redoubt_mem_swap_nonoverlapping
// ============================================================================

test_what_the_routine_leaves!(
    test_swap_nonoverlapping_leaves_the_residue_its_case_declares,
    redoubt_mem_swap_nonoverlapping,
    fn(*mut u8, *mut u8, usize),
    [dirty_swap_registers, dirty_swap_low, dirty_swap_high, untouched_swap],
    for bytes in LENGTHS,
    {
        let mut left = said(bytes);
        let mut right: Vec<u8> = said(bytes).iter().map(|byte| !byte).collect();
        let a = left.as_mut_ptr();
        let b = right.as_mut_ptr();
    },
    (a, b, bytes)
);

// ============================================================================
// redoubt_mem_is_utf8
// ============================================================================

test_what_the_routine_leaves!(
    test_is_utf8_leaves_the_residue_its_case_declares,
    redoubt_mem_is_utf8,
    fn(*const u8, usize, *mut u8),
    [dirty_is_utf8_registers, dirty_is_utf8_low, dirty_is_utf8_high, untouched_is_utf8],
    for text in TEXTS,
    {
        let mut answer = 0_u8;
        let bytes = text.as_ptr();
        let len = text.len();
        let answer = &raw mut answer;
    },
    (bytes, len, answer)
);

// ============================================================================
// redoubt_mem_is_zeroized
// ============================================================================

test_what_the_routine_leaves!(
    test_is_zeroized_leaves_the_residue_its_case_declares,
    redoubt_mem_is_zeroized,
    fn(*const u8, usize, *mut u8),
    [
        dirty_is_zeroized_registers,
        dirty_is_zeroized_low,
        dirty_is_zeroized_high,
        untouched_is_zeroized
    ],
    for len in LENGTHS,
    {
        let held = said(len);
        let mut answer = 0_u8;
        let bytes = held.as_ptr();
        let answer = &raw mut answer;
    },
    (bytes, len, answer)
);
