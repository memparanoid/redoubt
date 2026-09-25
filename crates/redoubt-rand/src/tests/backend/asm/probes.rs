// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the routine leaves in the registers, and whether the verifier that
//! answers that reads all of them. The routine takes no frame, so nothing here
//! measures one.

use rstest::rstest;

unsafe extern "C" {
    fn redoubt_rand_fill(dst: *mut u8, len: usize, answer: *mut u8);

    fn redoubt_rand_registers_are_zeroized() -> u64;
    fn redoubt_rand_dirty_registers();
}

/// What the register writer leaves in every register of the budget.
const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

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
                    empty_generals!(),
                    concat!("mov ", $register, ", {poison}"),
                    "call {verifier}",
                    poison = const POISON,
                    verifier = sym redoubt_rand_registers_are_zeroized,
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
                    empty_generals!(),
                    concat!("movz ", $register, ", #0xa5a5"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #16"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #32"),
                    concat!("movk ", $register, ", #0xa5a5, lsl #48"),
                    "bl {verifier}",
                    verifier = sym redoubt_rand_registers_are_zeroized,
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
            empty_generals!(),
            "call {verifier}",
            verifier = sym redoubt_rand_registers_are_zeroized,
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
            empty_generals!(),
            "bl {verifier}",
            verifier = sym redoubt_rand_registers_are_zeroized,
            lateout("x0") dirty,
            clobber_abi("C"),
        );
    }

    dirty
}

/// Every register of the budget as the writer leaves it, stored rather than
/// asked: the verifier answers with an OR, and an OR cannot say which register
/// carried it.
#[cfg(target_arch = "x86_64")]
fn capture_the_general_writer() -> [u64; GENERAL.len()] {
    let mut actual = [0_u64; GENERAL.len()];

    // SAFETY: the writer takes no argument and leaves r12 alone, which holds
    // the destination across the call. `actual` is one word per register, and
    // the stores cover it once each.
    unsafe {
        core::arch::asm!(
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
            writer = sym redoubt_rand_dirty_registers,
            inlateout("r12") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    actual
}

/// Every register of the budget as the writer leaves it, stored rather than
/// asked: the verifier answers with an OR, and an OR cannot say which register
/// carried it.
#[cfg(target_arch = "aarch64")]
fn capture_the_general_writer() -> [u64; GENERAL.len()] {
    let mut actual = [0_u64; GENERAL.len()];

    // SAFETY: the writer takes no argument and leaves x20 alone, which holds
    // the destination across the call. `actual` is one word per register, and
    // the stores cover it once each.
    unsafe {
        core::arch::asm!(
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
            writer = sym redoubt_rand_dirty_registers,
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

/// The routine through a pointer, then the verifier, in one block: nothing Rust
/// emits runs between them.
#[cfg(target_arch = "x86_64")]
macro_rules! measure {
    ($routine:expr, $a0:expr, $a1:expr, $a2:expr $(,)?) => {{
        let registers: u64;

        core::arch::asm!(
            "call r11",
            "call {register_probe}",
            register_probe = sym redoubt_rand_registers_are_zeroized,
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
            register_probe = sym redoubt_rand_registers_are_zeroized,
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
/// writer filled. The one that does nothing measures the gap: without it, a
/// clean reading of the real routine could be the call site having tidied up.
macro_rules! controls {
    ($registers:ident, $untouched:ident, ($($kind:ty),*)) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $untouched($(_: $kind),*) {
            core::arch::naked_asm!("ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $registers($(_: $kind),*) {
            core::arch::naked_asm!(
                tail_branch!(),
                target = sym redoubt_rand_dirty_registers,
            );
        }
    };
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
        Left::Everything => {
            assert_ne!(
                registers, 0,
                "a call that ran nothing emptied the registers"
            );
        }
        Left::Registers => {
            assert_ne!(
                registers, 0,
                "registers the replacement left full read as empty"
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
        [$registers:ident, $untouched:ident],
        for $each:ident in $over:expr,
        { $($setup:tt)* },
        ($($argument:expr),*)
    ) => {
        controls!($registers, $untouched, ($($kind),*));

        #[rstest]
        #[case::registers_left_full($registers as unsafe extern "C" fn($($kind),*), Left::Registers)]
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
                // width the routine reads or writes, or null where the kernel
                // is meant to refuse it.
                let registers = unsafe {
                    redoubt_rand_dirty_registers();
                    measure!(routine, $($argument),*)
                };

                assert_residue(registers, left);
            }
        }
    };
}

// ============================================================================
// redoubt_rand_registers_are_zeroized
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
    use super::{POISON, redoubt_rand_registers_are_zeroized};

    every_register!();
}

/// A register in the list and missing from the tests is reported filled by the
/// capture while the verifier is never asked about it.
#[test]
fn test_the_list_names_as_many_registers_as_there_are_tests() {
    assert_eq!(GENERAL.len(), every_register::GENERAL_TESTS);
}

// ============================================================================
// redoubt_rand_dirty_registers
// ============================================================================

/// A writer short by one register would let every negative below pass while
/// never dirtying the register the routine failed to wipe.
#[test]
fn test_dirty_registers_fills_every_register_in_the_budget() {
    let actual = capture_the_general_writer();

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(
            value, POISON,
            "{} came back from the writer empty",
            GENERAL[at]
        );
    }
}

// ============================================================================
// redoubt_rand_fill
// ============================================================================

/// Every length the wrapper hands over, from nothing to a whole piece, and a
/// destination the kernel refuses to write: both ways out of the routine.
const ASKED: [(usize, bool); 6] = [
    (0, true),
    (1, true),
    (32, true),
    (255, true),
    (256, true),
    (32, false),
];

test_what_the_routine_leaves!(
    test_fill_leaves_the_residue_its_case_declares,
    redoubt_rand_fill,
    fn(*mut u8, usize, *mut u8),
    [dirty_fill_registers, untouched_fill],
    for asked in ASKED,
    {
        let (len, writable) = asked;
        let mut into = std::vec![0_u8; len];
        let mut answer = 0_u8;
        let dst = if writable {
            into.as_mut_ptr()
        } else {
            core::ptr::null_mut()
        };
        let answer = &raw mut answer;
    },
    (dst, len, answer)
);
