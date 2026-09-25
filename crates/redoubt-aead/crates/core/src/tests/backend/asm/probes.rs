// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the comparison leaves in the registers, and whether the verifier that
//! answers that reads all of what it claims to. The routine takes no frame, so
//! there is no stack half.

use rstest::rstest;

unsafe extern "C" {
    fn redoubt_ct_eq(a: *const u8, b: *const u8, len: usize, out: *mut u8);

    fn redoubt_ct_registers_are_zeroized() -> u64;
    fn redoubt_ct_dirty_registers();
}

/// What the register writer leaves in every register of the budget.
const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// What a register holds before a writer is captured, so that a value the
/// capture finds is one the writer put there.
const STALE: u64 = 0x3c3c_3c3c_3c3c_3c3c;

type CtEq = unsafe extern "C" fn(*const u8, *const u8, usize, *mut u8);

// ============================================================================
// What differs between the targets
// ============================================================================

/// The budget as the assembly lists it, so that a failure names the register
/// rather than an index.
#[cfg(target_arch = "x86_64")]
const GENERAL: [&str; 9] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];

#[cfg(target_arch = "aarch64")]
const GENERAL: [&str; 18] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17",
];

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
                    empty_the_general_registers!(),
                    concat!("mov ", $register, ", {poison}"),
                    "call {verifier}",
                    poison = const POISON,
                    verifier = sym redoubt_ct_registers_are_zeroized,
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
                    empty_the_general_registers!(),
                    concat!("movz ", $register, ", #0xa5a5"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #16"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #32"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #48"),
                    "bl {verifier}",
                    verifier = sym redoubt_ct_registers_are_zeroized,
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

/// A test per entry of `GENERAL`, written by hand, and how many there are.
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

        pub(super) const GENERAL_TESTS: usize = 9;
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

        pub(super) const GENERAL_TESTS: usize = 18;
    };
}

#[cfg(target_arch = "x86_64")]
fn read_an_empty_register_file() -> u64 {
    let dirty: u64;

    // SAFETY: the verifier takes no argument and answers in rax, and every
    // caller-saved register is declared clobbered.
    unsafe {
        core::arch::asm!(
            empty_the_general_registers!(),
            "call {verifier}",
            verifier = sym redoubt_ct_registers_are_zeroized,
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
            empty_the_general_registers!(),
            "bl {verifier}",
            verifier = sym redoubt_ct_registers_are_zeroized,
            lateout("x0") dirty,
            clobber_abi("C"),
        );
    }

    dirty
}

/// Every register of the budget as the register writer leaves it, stored
/// rather than asked: the verifier answers with an OR, and an OR cannot say
/// which register carried it. The registers hold `STALE` going in.
#[cfg(target_arch = "x86_64")]
fn capture_the_register_writer() -> [u64; GENERAL.len()] {
    let mut actual = [0_u64; GENERAL.len()];

    // SAFETY: the writer takes no argument and leaves r12 alone, which holds
    // the destination across the call. `actual` is one word per register, and
    // the stores cover it once each.
    unsafe {
        core::arch::asm!(
            "mov rax, {stale}",
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
            stale = const STALE,
            writer = sym redoubt_ct_dirty_registers,
            inlateout("r12") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    actual
}

/// Every register of the budget as the register writer leaves it, stored
/// rather than asked: the verifier answers with an OR, and an OR cannot say
/// which register carried it. The registers hold `STALE` going in.
#[cfg(target_arch = "aarch64")]
fn capture_the_register_writer() -> [u64; GENERAL.len()] {
    let mut actual = [0_u64; GENERAL.len()];

    // SAFETY: the writer takes no argument and leaves x20 alone, which holds
    // the destination across the call. `actual` is one word per register, and
    // the stores cover it once each.
    unsafe {
        core::arch::asm!(
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
            writer = sym redoubt_ct_dirty_registers,
            inlateout("x20") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    actual
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

/// The one byte a stand-in writes through `out`, where the routine writes its
/// answer.
#[cfg(target_arch = "x86_64")]
macro_rules! answer_one {
    () => {
        "mov byte ptr [rcx], 1"
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! answer_one {
    () => {
        "mov w4, #1
         strb w4, [x3]"
    };
}

/// The routine through a pointer, then the verifier, in one block: nothing Rust
/// emits runs between them.
#[cfg(target_arch = "x86_64")]
macro_rules! measure {
    ($routine:expr, $a:expr, $b:expr, $len:expr, $out:expr $(,)?) => {{
        let registers: u64;

        core::arch::asm!(
            "call r11",
            "call {register_probe}",
            register_probe = sym redoubt_ct_registers_are_zeroized,
            inlateout("r11") $routine => _,
            inlateout("rdi") $a => _,
            inlateout("rsi") $b => _,
            inlateout("rdx") $len => _,
            inlateout("rcx") $out => _,
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
    ($routine:expr, $a:expr, $b:expr, $len:expr, $out:expr $(,)?) => {{
        let registers: u64;

        core::arch::asm!(
            "blr x16",
            "bl {register_probe}",
            register_probe = sym redoubt_ct_registers_are_zeroized,
            inlateout("x16") $routine => _,
            inlateout("x0") $a => registers,
            inlateout("x1") $b => _,
            inlateout("x2") $len => _,
            inlateout("x3") $out => _,
            clobber_abi("C"),
        );

        registers
    }};
}

/// Stand-ins for the routine, with its arguments and none of its work.
///
/// Naked and a tail branch, so no prologue of their own touches a register the
/// writer filled. The one that does nothing measures the gap: without it, a
/// clean reading of the real routine could be the call site having tidied up.
/// Both answer through `out` as the routine does, so the real case is the only
/// one whose answer is asserted.
#[unsafe(naked)]
unsafe extern "C" fn dirty_registers(_: *const u8, _: *const u8, _: usize, _: *mut u8) {
    core::arch::naked_asm!(
        answer_one!(),
        tail_branch!(),
        target = sym redoubt_ct_dirty_registers,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn untouched(_: *const u8, _: *const u8, _: usize, _: *mut u8) {
    core::arch::naked_asm!(answer_one!(), "ret");
}

/// Which residue a case deliberately leaves, or `Nothing` for the routine.
#[derive(Clone, Copy)]
enum Left {
    Registers,
    Everything,
    Nothing,
}

fn assert_residue(registers: u64, left: Left) {
    match left {
        Left::Registers => {
            assert_ne!(
                registers, 0,
                "registers the replacement left full read as empty"
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

// ============================================================================
// redoubt_ct_registers_are_zeroized
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
    use super::{POISON, redoubt_ct_registers_are_zeroized};

    every_register!();
}

#[test]
fn test_the_list_names_as_many_registers_as_there_are_tests() {
    assert_eq!(GENERAL.len(), every_register::GENERAL_TESTS);
}

// ============================================================================
// redoubt_ct_dirty_registers
// ============================================================================

/// A writer short by one register would let every negative below pass while
/// never dirtying the register the routine failed to wipe.
#[test]
fn test_dirty_registers_fills_every_register_in_the_budget() {
    let actual = capture_the_register_writer();

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(
            value, POISON,
            "{} came back from the writer empty",
            GENERAL[at]
        );
    }
}

// ============================================================================
// What the routines leave
// ============================================================================

// ============================================================================
// ct_eq
// ============================================================================

#[rstest]
#[case::registers_left_full(dirty_registers as CtEq, Left::Registers)]
#[case::nothing_ran(untouched as CtEq, Left::Everything)]
#[case::real(redoubt_ct_eq as CtEq, Left::Nothing)]
fn test_ct_eq_leaves_the_residue_its_case_declares(#[case] routine: CtEq, #[case] left: Left) {
    let routine = core::hint::black_box(routine);

    // Equal, and different in the last byte: both answers take the same
    // instructions, and both are measured.
    for last in [0x5a_u8, 0xa5] {
        // CORRECTNESS: the arguments are settled before the writer runs.
        // Anything computed after it runs in the registers it just filled.
        let a = [0x5a_u8; 16];
        let mut b = a;
        b[15] = last;
        let mut same = 0_u8;

        // SAFETY: both pointers are to sixteen readable bytes, the length says
        // so, and `same` is one writable byte that neither overlaps.
        let registers = unsafe {
            redoubt_ct_dirty_registers();
            measure!(routine, a.as_ptr(), b.as_ptr(), a.len(), &raw mut same)
        };

        assert_residue(registers, left);
    }
}
