// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each routine in the assembly leaves in the registers and in its frame,
//! and whether the verifiers that answer that read all of what they claim to.

use rstest::rstest;

use crate::consts::{BLOCK_SIZE, HASH_SIZE};

unsafe extern "C" {
    fn redoubt_sha256_compress_block(h: *mut u32, block: *const u8);
    fn redoubt_sha256_hash(msg: *const u8, msg_len: usize, digest: *mut u8);
    fn redoubt_hmac_sha256(
        key: *const u8,
        key_len: usize,
        msg: *const u8,
        msg_len: usize,
        mac: *mut u8,
    );
    fn redoubt_hkdf_sha256(
        salt: *const u8,
        salt_len: usize,
        ikm: *const u8,
        ikm_len: usize,
        info: *const u8,
        info_len: usize,
        okm: *mut u8,
        okm_len: usize,
    );

    fn redoubt_hkdf_probe_update_finalize(
        h: *mut u32,
        msg: *const u8,
        msg_len: usize,
        total_len: usize,
        digest: *mut u8,
    );
    fn redoubt_hkdf_probe_absorb(
        h: *mut u32,
        src: *const u8,
        len: usize,
        block: *mut u8,
        fill: *mut usize,
    );

    fn redoubt_hkdf_registers_are_zeroized() -> u64;
    fn redoubt_hkdf_dirty_registers();
    fn redoubt_hkdf_dirty_vector_low();
    fn redoubt_hkdf_dirty_vector_high();

    fn redoubt_hkdf_frame_is_zeroized_compress_block() -> u64;
    fn redoubt_hkdf_dirty_frame_compress_block(at: usize);
    fn redoubt_hkdf_clean_frame_compress_block();

    fn redoubt_hkdf_frame_is_zeroized_hash() -> u64;
    fn redoubt_hkdf_dirty_frame_hash(at: usize);
    fn redoubt_hkdf_clean_frame_hash();

    fn redoubt_hkdf_frame_is_zeroized_update_finalize() -> u64;
    fn redoubt_hkdf_dirty_frame_update_finalize(at: usize);
    fn redoubt_hkdf_clean_frame_update_finalize();

    fn redoubt_hkdf_frame_is_zeroized_hmac() -> u64;
    fn redoubt_hkdf_dirty_frame_hmac(at: usize);
    fn redoubt_hkdf_clean_frame_hmac();

    fn redoubt_hkdf_frame_is_zeroized_absorb() -> u64;
    fn redoubt_hkdf_dirty_frame_absorb(at: usize);
    fn redoubt_hkdf_clean_frame_absorb();

    fn redoubt_hkdf_frame_is_zeroized_hkdf() -> u64;
    fn redoubt_hkdf_dirty_frame_hkdf(at: usize);
    fn redoubt_hkdf_clean_frame_hkdf();
}

/// What the register writers leave in every register they fill.
const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// What a register holds before a writer is captured, so that a zero the
/// capture finds is one the writer put there.
const STALE: u64 = 0x3c3c_3c3c_3c3c_3c3c;

/// What the frame writer leaves, at the one offset it is asked for.
const LEFT_BYTE: u8 = 0x5c;

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

/// Each routine's frame, as its `.set FRAME_*` declares it. The targets differ:
/// x86-64 keeps more in registers, AArch64 a slot for the link register.
#[cfg(target_arch = "x86_64")]
mod frames {
    pub(super) const COMPRESS_BLOCK: usize = 72;
    pub(super) const HASH: usize = 200;
    pub(super) const UPDATE_FINALIZE: usize = 200;
    pub(super) const HMAC: usize = 328;
    pub(super) const ABSORB: usize = 40;
    pub(super) const HKDF: usize = 376;
}

#[cfg(target_arch = "aarch64")]
mod frames {
    pub(super) const COMPRESS_BLOCK: usize = 64;
    pub(super) const HASH: usize = 208;
    pub(super) const UPDATE_FINALIZE: usize = 208;
    pub(super) const HMAC: usize = 336;
    pub(super) const ABSORB: usize = 48;
    pub(super) const HKDF: usize = 384;
}

use frames::{
    ABSORB as FRAME_ABSORB, COMPRESS_BLOCK as FRAME_COMPRESS_BLOCK, HASH as FRAME_HASH,
    HKDF as FRAME_HKDF, HMAC as FRAME_HMAC, UPDATE_FINALIZE as FRAME_UPDATE_FINALIZE,
};

/// One line per register: a loop needs a counter, and the counter would be one
/// of the registers being emptied.
#[cfg(target_arch = "x86_64")]
macro_rules! empty_the_general_registers {
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
macro_rules! empty_the_general_registers {
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

#[cfg(target_arch = "x86_64")]
macro_rules! empty_the_vector_registers {
    () => {
        "pxor xmm0, xmm0
         pxor xmm1, xmm1
         pxor xmm2, xmm2
         pxor xmm3, xmm3
         pxor xmm4, xmm4
         pxor xmm5, xmm5
         pxor xmm6, xmm6
         pxor xmm7, xmm7
         pxor xmm8, xmm8
         pxor xmm9, xmm9
         pxor xmm10, xmm10
         pxor xmm11, xmm11
         pxor xmm12, xmm12
         pxor xmm13, xmm13
         pxor xmm14, xmm14
         pxor xmm15, xmm15"
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! empty_the_vector_registers {
    () => {
        "movi v0.16b, #0
         movi v1.16b, #0
         movi v2.16b, #0
         movi v3.16b, #0
         movi v4.16b, #0
         movi v5.16b, #0
         movi v6.16b, #0
         movi v7.16b, #0
         movi v16.16b, #0
         movi v17.16b, #0
         movi v18.16b, #0
         movi v19.16b, #0
         movi v20.16b, #0
         movi v21.16b, #0
         movi v22.16b, #0
         movi v23.16b, #0
         movi v24.16b, #0
         movi v25.16b, #0
         movi v26.16b, #0
         movi v27.16b, #0
         movi v28.16b, #0
         movi v29.16b, #0
         movi v30.16b, #0
         movi v31.16b, #0"
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
                    empty_the_vector_registers!(),
                    empty_the_general_registers!(),
                    concat!("mov ", $register, ", {poison}"),
                    "call {verifier}",
                    poison = const POISON,
                    verifier = sym redoubt_hkdf_registers_are_zeroized,
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
                    empty_the_vector_registers!(),
                    empty_the_general_registers!(),
                    concat!("movz ", $register, ", #0xa5a5"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #16"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #32"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #48"),
                    "bl {verifier}",
                    verifier = sym redoubt_hkdf_registers_are_zeroized,
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

/// One half of one vector register filled, everything else emptied, and the
/// verifier asked: a test for each half, since the verifier folds the high one
/// down to the width of its answer and a fold that dropped it would still see
/// the low one.
///
/// The pattern goes through rax, and the generals are emptied after it so rax
/// does not reach the call holding it.
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
                    empty_the_vector_registers!(),
                    "mov rax, {poison}",
                    concat!("movq ", $register, ", rax"),
                    $shift,
                    empty_the_general_registers!(),
                    "call {verifier}",
                    poison = const POISON,
                    verifier = sym redoubt_hkdf_registers_are_zeroized,
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

/// One lane of one vector register filled, everything else emptied, and the
/// verifier asked: a test for each lane, since the verifier folds the high one
/// down to the width of its answer and a fold that dropped it would still see
/// the low one.
///
/// The pattern goes through x0, and the generals are emptied after it so x0
/// does not reach the call holding it.
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
                    empty_the_vector_registers!(),
                    "movz x0, #0xa5a5",
                    "movk x0, #0xa5a5, lsl #16",
                    "movk x0, #0xa5a5, lsl #32",
                    "movk x0, #0xa5a5, lsl #48",
                    concat!("mov ", $register, ".d[", $lane, "], x0"),
                    empty_the_general_registers!(),
                    "bl {verifier}",
                    verifier = sym redoubt_hkdf_registers_are_zeroized,
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
            empty_the_vector_registers!(),
            empty_the_general_registers!(),
            "call {verifier}",
            verifier = sym redoubt_hkdf_registers_are_zeroized,
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
            empty_the_vector_registers!(),
            empty_the_general_registers!(),
            "bl {verifier}",
            verifier = sym redoubt_hkdf_registers_are_zeroized,
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
                empty_the_vector_registers!(),
                empty_the_general_registers!(),
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
                empty_the_vector_registers!(),
                "movz x0, #{stale0}",
                "movk x0, #{stale1}, lsl #16",
                "movk x0, #{stale2}, lsl #32",
                "movk x0, #{stale3}, lsl #48",
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
                stale0 = const STALE & 0xffff,
                stale1 = const (STALE >> 16) & 0xffff,
                stale2 = const (STALE >> 32) & 0xffff,
                stale3 = const STALE >> 48,
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
                empty_the_general_registers!(),
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
                "movz x0, #{stale0}",
                "movk x0, #{stale1}, lsl #16",
                "movk x0, #{stale2}, lsl #32",
                "movk x0, #{stale3}, lsl #48",
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
                empty_the_general_registers!(),
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
                stale0 = const STALE & 0xffff,
                stale1 = const (STALE >> 16) & 0xffff,
                stale2 = const (STALE >> 32) & 0xffff,
                stale3 = const STALE >> 48,
                writer = sym $writer,
                inlateout("x20") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        actual
    }};
}

/// Every byte of a frame as the frame writer leaves it, over a frame filled
/// with the poison first. Filling, calling and copying out are one block, so
/// nothing but the writer touches the window in between.
#[cfg(target_arch = "x86_64")]
macro_rules! capture_the_frame_writer {
    ($size:expr, $writer:path, $at:expr) => {{
        let mut actual = [0xff_u8; $size];

        // SAFETY: the offset is inside the writer's frame and `actual` is as
        // long as it. r12 holds the destination across the call and the writer
        // leaves it alone. The reservation is the frame and the return-address
        // slot plus eight, so after reserving again the writer's frame is
        // `[rsp + 8, rsp + 8 + size)`.
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
                window = const $size + 16,
                frame = const $size,
                poison = const POISON,
                writer = sym $writer,
                inlateout("rdi") $at => _,
                inlateout("r12") actual.as_mut_ptr() => _,
                clobber_abi("C"),
            );
        }

        actual
    }};
}

/// Every byte of a frame as the frame writer leaves it, over a frame filled
/// with the poison first. Filling, calling and copying out are one block, so
/// nothing but the writer touches the window in between.
#[cfg(target_arch = "aarch64")]
macro_rules! capture_the_frame_writer {
    ($size:expr, $writer:path, $at:expr) => {{
        let mut actual = [0xff_u8; $size];

        // SAFETY: the offset is inside the writer's frame and `actual` is as
        // long as it. x20 holds the destination across the call and the writer
        // leaves it alone. `bl` writes no stack, so reserving the frame again
        // gives exactly the writer's frame.
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
                frame = const $size,
                writer = sym $writer,
                inlateout("x0") $at => _,
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

/// The first argument set to zero, which is the offset the frame writer reads.
#[cfg(target_arch = "x86_64")]
macro_rules! offset_zero {
    () => {
        "xor edi, edi"
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! offset_zero {
    () => {
        "mov x0, xzr"
    };
}

/// The routine through a pointer, then both verifiers, in one block: nothing
/// Rust emits runs between them, and they all run at the stack pointer the
/// routine was entered with. The register verdict waits in r12 while the frame
/// is read, since reading it takes registers.
#[cfg(target_arch = "x86_64")]
macro_rules! measure {
    ($routine:expr, $frame_probe:path, $a0:expr, $a1:expr $(,)?) => {
        measure!(@call $routine, $frame_probe, [("rdi") $a0, ("rsi") $a1])
    };
    ($routine:expr, $frame_probe:path, $a0:expr, $a1:expr, $a2:expr $(,)?) => {
        measure!(@call $routine, $frame_probe,
                 [("rdi") $a0, ("rsi") $a1, ("rdx") $a2])
    };
    ($routine:expr, $frame_probe:path,
     $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr $(,)?) => {
        measure!(@call $routine, $frame_probe,
                 [("rdi") $a0, ("rsi") $a1, ("rdx") $a2, ("rcx") $a3, ("r8") $a4])
    };
    (@call $routine:expr, $frame_probe:path, [$(($register:tt) $argument:expr),* $(,)?]) => {{
        let registers: u64;
        let frame: u64;

        core::arch::asm!(
            "call r11",
            "call {register_probe}",
            "mov r12, rax",
            "call {frame_probe}",
            register_probe = sym redoubt_hkdf_registers_are_zeroized,
            frame_probe = sym $frame_probe,
            inlateout("r11") $routine => _,
            $(inlateout($register) $argument => _,)*
            lateout("r12") registers,
            lateout("rax") frame,
            clobber_abi("C"),
        );

        (registers, frame)
    }};
}

/// The routine through a pointer, then both verifiers, in one block: nothing
/// Rust emits runs between them, and they all run at the stack pointer the
/// routine was entered with. Each verdict leaves x0 for a callee-saved register
/// before the next call can overwrite it.
#[cfg(target_arch = "aarch64")]
macro_rules! measure {
    ($routine:expr, $frame_probe:path, $a0:expr, $a1:expr $(,)?) => {
        measure!(@call $routine, $frame_probe, [("x0") $a0, ("x1") $a1])
    };
    ($routine:expr, $frame_probe:path, $a0:expr, $a1:expr, $a2:expr $(,)?) => {
        measure!(@call $routine, $frame_probe,
                 [("x0") $a0, ("x1") $a1, ("x2") $a2])
    };
    ($routine:expr, $frame_probe:path,
     $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr $(,)?) => {
        measure!(@call $routine, $frame_probe,
                 [("x0") $a0, ("x1") $a1, ("x2") $a2, ("x3") $a3, ("x4") $a4])
    };
    ($routine:expr, $frame_probe:path,
     $a0:expr, $a1:expr, $a2:expr, $a3:expr,
     $a4:expr, $a5:expr, $a6:expr, $a7:expr $(,)?) => {
        measure!(@call $routine, $frame_probe,
                 [("x0") $a0, ("x1") $a1, ("x2") $a2, ("x3") $a3,
                  ("x4") $a4, ("x5") $a5, ("x6") $a6, ("x7") $a7])
    };
    (@call $routine:expr, $frame_probe:path, [$(($register:tt) $argument:expr),* $(,)?]) => {{
        let registers: u64;
        let frame: u64;

        core::arch::asm!(
            "blr x16",
            "bl {register_probe}",
            "mov x20, x0",
            "bl {frame_probe}",
            "mov x21, x0",
            register_probe = sym redoubt_hkdf_registers_are_zeroized,
            frame_probe = sym $frame_probe,
            inlateout("x16") $routine => _,
            $(inlateout($register) $argument => _,)*
            lateout("x20") registers,
            lateout("x21") frame,
            clobber_abi("C"),
        );

        (registers, frame)
    }};
}

/// The measurement of a routine whose seventh and eighth arguments SysV passes
/// on the stack, with the frame dirtied at `$at` from inside the block.
///
/// The reservation that carries them is kept until both verifiers have run:
/// given back any earlier, the frame verifier would read above the frame the
/// routine used. The writer runs after the reservation, since one called
/// before the block fills a window the routine does not use. The offset
/// arrives in r13, outside the budget, and the first argument waits on the
/// stack while the writer takes rdi.
#[cfg(target_arch = "x86_64")]
macro_rules! measure_with_stack_arguments {
    (
        $routine:expr, $frame_probe:path, $frame_writer:path, $at:expr,
        $first:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr,
        $seventh:expr, $eighth:expr $(,)?
    ) => {{
        let registers: u64;
        let frame: u64;

        core::arch::asm!(
            "sub rsp, 32",
            "mov [rsp + 16], rdi",
            "mov rdi, r13",
            "call {frame_writer}",
            "mov rdi, [rsp + 16]",
            "mov [rsp], r14",
            "mov [rsp + 8], r15",
            "call r11",
            "call {register_probe}",
            "mov r12, rax",
            "call {frame_probe}",
            "add rsp, 32",
            register_probe = sym redoubt_hkdf_registers_are_zeroized,
            frame_probe = sym $frame_probe,
            frame_writer = sym $frame_writer,
            inlateout("r11") $routine => _,
            inlateout("rdi") $first => _,
            inlateout("rsi") $a1 => _,
            inlateout("rdx") $a2 => _,
            inlateout("rcx") $a3 => _,
            inlateout("r8") $a4 => _,
            inlateout("r9") $a5 => _,
            inlateout("r13") $at => _,
            inlateout("r14") $seventh => _,
            inlateout("r15") $eighth => _,
            lateout("r12") registers,
            lateout("rax") frame,
            clobber_abi("C"),
        );

        (registers, frame)
    }};
}

/// The frame dirtied at `$at`, then the measurement. AAPCS passes every
/// argument in a register, so nothing is reserved and the writer's window is
/// the routine's.
#[cfg(target_arch = "aarch64")]
macro_rules! measure_with_stack_arguments {
    (
        $routine:expr, $frame_probe:path, $frame_writer:path, $at:expr,
        $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr,
        $a6:expr, $a7:expr $(,)?
    ) => {{
        $frame_writer($at);
        measure!(
            $routine,
            $frame_probe,
            $a0,
            $a1,
            $a2,
            $a3,
            $a4,
            $a5,
            $a6,
            $a7
        )
    }};
}

/// Stand-ins for a routine, with its arguments and none of its work.
///
/// Naked and a tail branch, so the caller's stack pointer and return address
/// are what the writer sees. The one that does nothing measures the gap:
/// without it, a clean reading of the real routine could be the call site
/// having tidied up.
macro_rules! controls {
    (
        [$registers:ident, $low:ident, $high:ident, $frame:ident, $untouched:ident],
        $dirty_frame:path, ($($kind:ty),*)
    ) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $untouched($(_: $kind),*) {
            core::arch::naked_asm!("ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $registers($(_: $kind),*) {
            core::arch::naked_asm!(
                tail_branch!(),
                target = sym redoubt_hkdf_dirty_registers,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $low($(_: $kind),*) {
            core::arch::naked_asm!(
                tail_branch!(),
                target = sym redoubt_hkdf_dirty_vector_low,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $high($(_: $kind),*) {
            core::arch::naked_asm!(
                tail_branch!(),
                target = sym redoubt_hkdf_dirty_vector_high,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $frame($(_: $kind),*) {
            core::arch::naked_asm!(
                offset_zero!(),
                tail_branch!(),
                target = sym $dirty_frame,
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
    Frame,
    Everything,
    Nothing,
}

/// Each negative asks only about the residue it leaves. A half left full is
/// asserted exactly: every other bit of the budget is empty, so `POISON` can
/// only come through that half.
fn assert_residue(registers: u64, frame: u64, left: Left) {
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
        Left::Frame => {
            assert_ne!(
                frame, 0,
                "the frame the replacement left full reads as empty"
            );
        }
        Left::Everything => {
            assert_ne!(
                registers, 0,
                "a call that ran nothing emptied the registers"
            );
            assert_ne!(frame, 0, "a call that ran nothing emptied the frame");
        }
        Left::Nothing => {
            // Assert zeroization!
            assert_eq!(registers, 0, "the registers after the real routine");
            assert_eq!(frame, 0, "the frame after the real routine");
        }
    }
}

/// The stand-ins for a routine and its cases, the negatives first. The `for`
/// clause, where there is one, measures the routine once per value it walks.
macro_rules! test_what_the_routine_leaves {
    (
        $name:ident, $real:path, fn($($kind:ty),*),
        [$registers:ident, $low:ident, $high:ident, $frame:ident, $untouched:ident],
        $dirty_frame:path, $verify:path,
        $(for $each:ident in $over:expr,)?
        { $($setup:tt)* },
        ($($argument:expr),*)
    ) => {
        controls!(
            [$registers, $low, $high, $frame, $untouched],
            $dirty_frame,
            ($($kind),*)
        );

        #[rstest]
        #[case::registers_left_full($registers as unsafe extern "C" fn($($kind),*), Left::Registers)]
        #[case::low_left_full($low as unsafe extern "C" fn($($kind),*), Left::VectorLows)]
        #[case::high_left_full($high as unsafe extern "C" fn($($kind),*), Left::VectorHighs)]
        #[case::frame_left_full($frame as unsafe extern "C" fn($($kind),*), Left::Frame)]
        #[case::nothing_ran($untouched as unsafe extern "C" fn($($kind),*), Left::Everything)]
        #[case::real($real as unsafe extern "C" fn($($kind),*), Left::Nothing)]
        fn $name(#[case] routine: unsafe extern "C" fn($($kind),*), #[case] left: Left) {
            let routine = core::hint::black_box(routine);

            $(for $each in $over)? {
                // CORRECTNESS: the arguments are settled before the writers
                // run. Anything computed after them runs on the stack they just
                // filled.
                $($setup)*

                // SAFETY: every pointer the setup binds is to storage of the
                // width the routine reads or writes, and none of them overlap.
                let (registers, frame) = unsafe {
                    redoubt_hkdf_dirty_registers();
                    $dirty_frame(0);
                    measure!(routine, $verify, $($argument),*)
                };

                assert_residue(registers, frame, left);
            }
        }
    };
}

/// One byte left at every offset of the window, then the routine's own call
/// site with the stand-in that does nothing: the verifier has to find that byte
/// and nothing else.
macro_rules! test_the_measurement_reads_the_window {
    (
        $name:ident, $untouched:ident, fn($($kind:ty),*),
        $size:expr, $dirty_frame:path, $verify:path,
        { $($setup:tt)* },
        ($($argument:expr),*)
    ) => {
        #[test]
        fn $name() {
            // CORRECTNESS: the arguments are settled before the writers run.
            // Anything computed after them runs on the stack they just filled.
            $($setup)*

            for at in 0..$size {
                // SAFETY: the offset is inside the writer's frame, and the
                // stand-in never reads what it is handed.
                let (_, frame) = unsafe {
                    $dirty_frame(at);
                    measure!(
                        $untouched as unsafe extern "C" fn($($kind),*),
                        $verify,
                        $($argument),*
                    )
                };

                assert_eq!(
                    frame,
                    only_the_byte_at(at),
                    "byte {at} of the frame does not reach the answer"
                );
            }
        }
    };
}

// ============================================================================
// redoubt_hkdf_registers_are_zeroized
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
    use super::{POISON, redoubt_hkdf_registers_are_zeroized};

    every_register!();
}

#[test]
fn test_the_lists_name_as_many_registers_as_there_are_tests() {
    assert_eq!(GENERAL.len(), every_register::GENERAL_TESTS);
    assert_eq!(VECTOR.len(), every_register::VECTOR_TESTS);
}

// ============================================================================
// redoubt_hkdf_frame_is_zeroized_*
// ============================================================================

/// One byte left at every offset of a frame, and the verifier asked after each;
/// then a frame written and emptied, which has to read as empty. The sweep is
/// what shows the verifier reads the whole window, and an off-by-one at either
/// end shows here and nowhere else.
macro_rules! test_the_frame_verifier_reads_its_whole_window {
    ($sweep:ident, $positive:ident, $size:expr, $dirty:path, $clean:path, $verify:path) => {
        #[test]
        fn $sweep() {
            for at in 0..$size {
                // SAFETY: the offset is inside the frame the writer takes, and
                // the verifier reads the frame the writer gave back.
                let dirty = unsafe {
                    $dirty(at);
                    $verify()
                };

                assert_eq!(
                    dirty,
                    only_the_byte_at(at),
                    "byte {at} of the frame does not reach the answer"
                );
            }
        }

        #[test]
        fn $positive() {
            // SAFETY: the writer fills and empties the frame it takes, and the
            // verifier reads the frame it gave back.
            let dirty = unsafe {
                $clean();
                $verify()
            };

            // Assert zeroization!
            assert_eq!(dirty, 0, "a frame that was emptied reads as full");
        }
    };
}

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_compress_block_frame_is_seen,
    test_a_compress_block_frame_written_and_emptied_reads_as_empty,
    FRAME_COMPRESS_BLOCK,
    redoubt_hkdf_dirty_frame_compress_block,
    redoubt_hkdf_clean_frame_compress_block,
    redoubt_hkdf_frame_is_zeroized_compress_block
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_hash_frame_is_seen,
    test_a_hash_frame_written_and_emptied_reads_as_empty,
    FRAME_HASH,
    redoubt_hkdf_dirty_frame_hash,
    redoubt_hkdf_clean_frame_hash,
    redoubt_hkdf_frame_is_zeroized_hash
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_update_finalize_frame_is_seen,
    test_an_update_finalize_frame_written_and_emptied_reads_as_empty,
    FRAME_UPDATE_FINALIZE,
    redoubt_hkdf_dirty_frame_update_finalize,
    redoubt_hkdf_clean_frame_update_finalize,
    redoubt_hkdf_frame_is_zeroized_update_finalize
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_hmac_frame_is_seen,
    test_an_hmac_frame_written_and_emptied_reads_as_empty,
    FRAME_HMAC,
    redoubt_hkdf_dirty_frame_hmac,
    redoubt_hkdf_clean_frame_hmac,
    redoubt_hkdf_frame_is_zeroized_hmac
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_absorb_frame_is_seen,
    test_an_absorb_frame_written_and_emptied_reads_as_empty,
    FRAME_ABSORB,
    redoubt_hkdf_dirty_frame_absorb,
    redoubt_hkdf_clean_frame_absorb,
    redoubt_hkdf_frame_is_zeroized_absorb
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_hkdf_frame_is_seen,
    test_an_hkdf_frame_written_and_emptied_reads_as_empty,
    FRAME_HKDF,
    redoubt_hkdf_dirty_frame_hkdf,
    redoubt_hkdf_clean_frame_hkdf,
    redoubt_hkdf_frame_is_zeroized_hkdf
);

// ============================================================================
// redoubt_hkdf_dirty_registers
// ============================================================================

/// A writer short by one register would let every negative below pass while
/// never dirtying the register the routine failed to wipe.
#[test]
fn test_dirty_registers_fills_every_general_register_in_the_budget() {
    let actual = capture_the_general_writer!(redoubt_hkdf_dirty_registers);

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(
            value, POISON,
            "{} came back from the writer empty",
            GENERAL[at]
        );
    }
}

#[test]
fn test_dirty_registers_fills_every_vector_register_in_the_budget() {
    let actual = capture_the_vector_writer!(redoubt_hkdf_dirty_registers);

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
// redoubt_hkdf_dirty_vector_low
// ============================================================================

#[test]
fn test_dirty_vector_low_empties_every_general_register_in_the_budget() {
    let actual = capture_the_general_writer!(redoubt_hkdf_dirty_vector_low);

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(value, 0, "{} came back from the writer full", GENERAL[at]);
    }
}

#[test]
fn test_dirty_vector_low_fills_only_the_low_half_of_every_vector_register() {
    let actual = capture_the_vector_writer!(redoubt_hkdf_dirty_vector_low);

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
// redoubt_hkdf_dirty_vector_high
// ============================================================================

#[test]
fn test_dirty_vector_high_empties_every_general_register_in_the_budget() {
    let actual = capture_the_general_writer!(redoubt_hkdf_dirty_vector_high);

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(value, 0, "{} came back from the writer full", GENERAL[at]);
    }
}

#[test]
fn test_dirty_vector_high_fills_only_the_high_half_of_every_vector_register() {
    let actual = capture_the_vector_writer!(redoubt_hkdf_dirty_vector_high);

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
// redoubt_hkdf_dirty_frame_*
// ============================================================================

/// Through the verifier, residue from an earlier call and the byte this one
/// wrote give the same answer, so this is the only test that catches a writer
/// that does not empty the frame first.
macro_rules! test_the_frame_writer_leaves_one_byte {
    ($name:ident, $size:expr, $writer:path) => {
        #[test]
        fn $name() {
            for at in 0..$size {
                let actual = capture_the_frame_writer!($size, $writer, at);

                for (byte, &value) in actual.iter().enumerate() {
                    assert_eq!(
                        value,
                        if byte == at { LEFT_BYTE } else { 0 },
                        "requested byte {at}, captured byte {byte}",
                    );
                }
            }
        }
    };
}

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_compress_block_clears_every_byte_except_the_requested_one,
    FRAME_COMPRESS_BLOCK,
    redoubt_hkdf_dirty_frame_compress_block
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_hash_clears_every_byte_except_the_requested_one,
    FRAME_HASH,
    redoubt_hkdf_dirty_frame_hash
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_update_finalize_clears_every_byte_except_the_requested_one,
    FRAME_UPDATE_FINALIZE,
    redoubt_hkdf_dirty_frame_update_finalize
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_hmac_clears_every_byte_except_the_requested_one,
    FRAME_HMAC,
    redoubt_hkdf_dirty_frame_hmac
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_absorb_clears_every_byte_except_the_requested_one,
    FRAME_ABSORB,
    redoubt_hkdf_dirty_frame_absorb
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_hkdf_clears_every_byte_except_the_requested_one,
    FRAME_HKDF,
    redoubt_hkdf_dirty_frame_hkdf
);

// ============================================================================
// What the routines leave
// ============================================================================

/// The state SHA-256 starts from, for the routines that are handed one.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Past two blocks, so the routines reach the compression from inside and still
/// have a tail to pad.
const MESSAGE: [u8; 150] = [0x5a; 150];

/// Past a block, so HMAC hashes the key down before padding it.
const KEY: [u8; 100] = [0x0b; 100];

// ============================================================================
// sha256_compress_block
// ============================================================================

test_what_the_routine_leaves!(
    test_compress_block_leaves_the_residue_its_case_declares,
    redoubt_sha256_compress_block,
    fn(*mut u32, *const u8),
    [
        dirty_compress_registers,
        dirty_compress_low,
        dirty_compress_high,
        dirty_compress_frame,
        untouched_compress
    ],
    redoubt_hkdf_dirty_frame_compress_block,
    redoubt_hkdf_frame_is_zeroized_compress_block,
    {
        let mut h = H0;
        let block = [0x42_u8; BLOCK_SIZE];
        let h = h.as_mut_ptr();
        let block = block.as_ptr();
    },
    (h, block)
);

// ============================================================================
// sha256_hash
// ============================================================================

test_what_the_routine_leaves!(
    test_hash_leaves_the_residue_its_case_declares,
    redoubt_sha256_hash,
    fn(*const u8, usize, *mut u8),
    [dirty_hash_registers, dirty_hash_low, dirty_hash_high, dirty_hash_frame, untouched_hash],
    redoubt_hkdf_dirty_frame_hash,
    redoubt_hkdf_frame_is_zeroized_hash,
    // A tail of 55 still has room for the length after its padding; 56 is the
    // first that needs a second block.
    for length in [0, 1, 55, 56, 64, 65, MESSAGE.len()],
    {
        let mut digest = [0_u8; HASH_SIZE];
        let message = MESSAGE.as_ptr();
        let digest = digest.as_mut_ptr();
    },
    (message, length, digest)
);

// ============================================================================
// sha256_update_finalize
// ============================================================================

test_what_the_routine_leaves!(
    test_update_finalize_leaves_the_residue_its_case_declares,
    redoubt_hkdf_probe_update_finalize,
    fn(*mut u32, *const u8, usize, usize, *mut u8),
    [
        dirty_update_registers,
        dirty_update_low,
        dirty_update_high,
        dirty_update_frame,
        untouched_update
    ],
    redoubt_hkdf_dirty_frame_update_finalize,
    redoubt_hkdf_frame_is_zeroized_update_finalize,
    {
        let mut h = H0;
        let mut digest = [0_u8; HASH_SIZE];
        let h = h.as_mut_ptr();
        let message = MESSAGE.as_ptr();
        let length = MESSAGE.len();
        let digest = digest.as_mut_ptr();
    },
    (h, message, length, length, digest)
);

// ============================================================================
// sha256_absorb
// ============================================================================

test_what_the_routine_leaves!(
    test_absorb_leaves_the_residue_its_case_declares,
    redoubt_hkdf_probe_absorb,
    fn(*mut u32, *const u8, usize, *mut u8, *mut usize),
    [dirty_absorb_registers, dirty_absorb_low, dirty_absorb_high, dirty_absorb_frame, untouched_absorb],
    redoubt_hkdf_dirty_frame_absorb,
    redoubt_hkdf_frame_is_zeroized_absorb,
    // A whole block is the first run that reaches the compression from inside.
    for length in [0, 1, BLOCK_SIZE, MESSAGE.len()],
    {
        let mut h = H0;
        let mut block = [0_u8; BLOCK_SIZE];
        let mut fill = 0_usize;
        let h = h.as_mut_ptr();
        let message = MESSAGE.as_ptr();
        let block = block.as_mut_ptr();
        let fill = &raw mut fill;
    },
    (h, message, length, block, fill)
);

// ============================================================================
// hmac_sha256
// ============================================================================

test_what_the_routine_leaves!(
    test_hmac_leaves_the_residue_its_case_declares,
    redoubt_hmac_sha256,
    fn(*const u8, usize, *const u8, usize, *mut u8),
    [dirty_hmac_registers, dirty_hmac_low, dirty_hmac_high, dirty_hmac_frame, untouched_hmac],
    redoubt_hkdf_dirty_frame_hmac,
    redoubt_hkdf_frame_is_zeroized_hmac,
    for key_len in [BLOCK_SIZE, KEY.len()],
    {
        let mut mac = [0_u8; HASH_SIZE];
        let key = KEY.as_ptr();
        let message = MESSAGE.as_ptr();
        let length = MESSAGE.len();
        let mac = mac.as_mut_ptr();
    },
    (key, key_len, message, length, mac)
);

// ============================================================================
// hkdf_sha256
// ============================================================================

type Hkdf =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *mut u8, usize);

controls!(
    [
        dirty_hkdf_registers,
        dirty_hkdf_low,
        dirty_hkdf_high,
        dirty_hkdf_frame,
        untouched_hkdf
    ],
    redoubt_hkdf_dirty_frame_hkdf,
    (
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut u8,
        usize
    )
);

#[rstest]
#[case::registers_left_full(dirty_hkdf_registers as Hkdf, Left::Registers)]
#[case::low_left_full(dirty_hkdf_low as Hkdf, Left::VectorLows)]
#[case::high_left_full(dirty_hkdf_high as Hkdf, Left::VectorHighs)]
#[case::frame_left_full(dirty_hkdf_frame as Hkdf, Left::Frame)]
#[case::nothing_ran(untouched_hkdf as Hkdf, Left::Everything)]
#[case::real(redoubt_hkdf_sha256 as Hkdf, Left::Nothing)]
fn test_hkdf_leaves_the_residue_its_case_declares(#[case] routine: Hkdf, #[case] left: Left) {
    let routine = core::hint::black_box(routine);

    // Past one block of output is the only path that puts a previous T in the
    // frame.
    for wanted in [1, HASH_SIZE, 100] {
        // CORRECTNESS: the arguments are settled before the writers run.
        // Anything computed after them runs on the stack they just filled.
        let mut okm = [0_u8; 100];
        let key = KEY.as_ptr();
        let key_len = KEY.len();
        let message = MESSAGE.as_ptr();
        let length = MESSAGE.len();
        let okm = okm.as_mut_ptr();

        // SAFETY: each pointer is as long as the length beside it, the
        // destination has room for the length asked for, and that length is
        // inside what the counter has blocks for.
        let (registers, frame) = unsafe {
            redoubt_hkdf_dirty_registers();
            measure_with_stack_arguments!(
                routine,
                redoubt_hkdf_frame_is_zeroized_hkdf,
                redoubt_hkdf_dirty_frame_hkdf,
                0_usize,
                key,
                key_len,
                message,
                length,
                key,
                key_len,
                okm,
                wanted,
            )
        };

        assert_residue(registers, frame, left);
    }
}

// ============================================================================
// What the measurement reads
// ============================================================================

/// What the verifier answers when the only thing in the window is the byte left
/// at `at`: it ORs a word at a time, so the byte comes back in its place within
/// its word. Asserted exactly, because a window that slid reads bytes nobody
/// wrote, and "something was found" would take those for the byte.
fn only_the_byte_at(at: usize) -> u64 {
    u64::from(LEFT_BYTE) << (8 * (at % 8))
}

/// An offset that expected zero would turn "the byte was found" into "nothing
/// was found", and the sweep would pass exactly where the byte went missing.
#[test]
fn test_no_offset_expects_an_empty_window() {
    for at in 0..FRAME_HKDF {
        assert_ne!(only_the_byte_at(at), 0, "offset {at}");
    }
}

test_the_measurement_reads_the_window!(
    test_the_measurement_of_compress_block_reads_the_window_the_writer_filled,
    untouched_compress,
    fn(*mut u32, *const u8),
    FRAME_COMPRESS_BLOCK,
    redoubt_hkdf_dirty_frame_compress_block,
    redoubt_hkdf_frame_is_zeroized_compress_block,
    {
        let mut h = H0;
        let block = [0x42_u8; BLOCK_SIZE];
        let h = h.as_mut_ptr();
        let block = block.as_ptr();
    },
    (h, block)
);

test_the_measurement_reads_the_window!(
    test_the_measurement_of_hash_reads_the_window_the_writer_filled,
    untouched_hash,
    fn(*const u8, usize, *mut u8),
    FRAME_HASH,
    redoubt_hkdf_dirty_frame_hash,
    redoubt_hkdf_frame_is_zeroized_hash,
    {
        let mut digest = [0_u8; HASH_SIZE];
        let message = MESSAGE.as_ptr();
        let length = MESSAGE.len();
        let digest = digest.as_mut_ptr();
    },
    (message, length, digest)
);

test_the_measurement_reads_the_window!(
    test_the_measurement_of_update_finalize_reads_the_window_the_writer_filled,
    untouched_update,
    fn(*mut u32, *const u8, usize, usize, *mut u8),
    FRAME_UPDATE_FINALIZE,
    redoubt_hkdf_dirty_frame_update_finalize,
    redoubt_hkdf_frame_is_zeroized_update_finalize,
    {
        let mut h = H0;
        let mut digest = [0_u8; HASH_SIZE];
        let h = h.as_mut_ptr();
        let message = MESSAGE.as_ptr();
        let length = MESSAGE.len();
        let digest = digest.as_mut_ptr();
    },
    (h, message, length, length, digest)
);

test_the_measurement_reads_the_window!(
    test_the_measurement_of_absorb_reads_the_window_the_writer_filled,
    untouched_absorb,
    fn(*mut u32, *const u8, usize, *mut u8, *mut usize),
    FRAME_ABSORB,
    redoubt_hkdf_dirty_frame_absorb,
    redoubt_hkdf_frame_is_zeroized_absorb,
    {
        let mut h = H0;
        let mut block = [0_u8; BLOCK_SIZE];
        let mut fill = 0_usize;
        let h = h.as_mut_ptr();
        let message = MESSAGE.as_ptr();
        let length = MESSAGE.len();
        let block = block.as_mut_ptr();
        let fill = &raw mut fill;
    },
    (h, message, length, block, fill)
);

test_the_measurement_reads_the_window!(
    test_the_measurement_of_hmac_reads_the_window_the_writer_filled,
    untouched_hmac,
    fn(*const u8, usize, *const u8, usize, *mut u8),
    FRAME_HMAC,
    redoubt_hkdf_dirty_frame_hmac,
    redoubt_hkdf_frame_is_zeroized_hmac,
    {
        let mut mac = [0_u8; HASH_SIZE];
        let key = KEY.as_ptr();
        let key_len = KEY.len();
        let message = MESSAGE.as_ptr();
        let length = MESSAGE.len();
        let mac = mac.as_mut_ptr();
    },
    (key, key_len, message, length, mac)
);

#[test]
fn test_the_measurement_of_hkdf_reads_the_window_the_writer_filled() {
    let mut okm = [0_u8; 100];

    let key = KEY.as_ptr();
    let key_len = KEY.len();
    let message = MESSAGE.as_ptr();
    let length = MESSAGE.len();
    let wanted = okm.len();
    let okm = okm.as_mut_ptr();

    for at in 0..FRAME_HKDF {
        // SAFETY: the offset is inside the writer's frame, and the stand-in
        // never reads what it is handed.
        let (_, frame) = unsafe {
            measure_with_stack_arguments!(
                untouched_hkdf as Hkdf,
                redoubt_hkdf_frame_is_zeroized_hkdf,
                redoubt_hkdf_dirty_frame_hkdf,
                at,
                key,
                key_len,
                message,
                length,
                key,
                key_len,
                okm,
                wanted,
            )
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}
