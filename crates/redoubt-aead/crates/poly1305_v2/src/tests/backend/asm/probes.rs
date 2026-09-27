// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each routine in the assembly leaves in the registers and in its frame,
//! and whether the verifiers that answer that read all of what they claim to.

unsafe extern "C" {
    fn redoubt_poly1305_v2_registers_are_zeroized() -> u64;
    fn redoubt_poly1305_v2_dirty_registers();

    fn redoubt_poly1305_v2_frame_is_zeroized_poly1305() -> u64;
    fn redoubt_poly1305_v2_dirty_frame_poly1305(at: usize);
    fn redoubt_poly1305_v2_clean_frame_poly1305();
}

/// What the register writer leaves in every register of the budget.
const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// What a register holds before a writer is captured, so that a value the
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

#[cfg(target_arch = "aarch64")]
const GENERAL: [&str; 18] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17",
];

/// The frame, as its `.set FRAME` declares it: congruent to eight modulo
/// sixteen on x86-64, a multiple of sixteen on AArch64, which pads its slots by
/// eight to get there.
#[cfg(target_arch = "x86_64")]
const FRAME: usize = 104;

#[cfg(target_arch = "aarch64")]
const FRAME: usize = 112;

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
                    verifier = sym redoubt_poly1305_v2_registers_are_zeroized,
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
                    verifier = sym redoubt_poly1305_v2_registers_are_zeroized,
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
            verifier = sym redoubt_poly1305_v2_registers_are_zeroized,
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
            verifier = sym redoubt_poly1305_v2_registers_are_zeroized,
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
            writer = sym redoubt_poly1305_v2_dirty_registers,
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
            writer = sym redoubt_poly1305_v2_dirty_registers,
            inlateout("x20") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    actual
}

/// Every byte of the frame as the frame writer leaves it, over a frame filled
/// with the poison first. Filling, calling and copying out are one block, so
/// nothing but the writer touches the window in between.
#[cfg(target_arch = "x86_64")]
fn capture_the_frame_writer(at: usize) -> [u8; FRAME] {
    let mut actual = [0xff_u8; FRAME];

    // SAFETY: the offset is inside the writer's frame and `actual` is as long
    // as it. r12 holds the destination across the call and the writer leaves
    // it alone. The reservation is the frame and the return-address slot plus
    // eight, so after reserving again the writer's frame is
    // `[rsp + 8, rsp + 8 + FRAME)`.
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
            writer = sym redoubt_poly1305_v2_dirty_frame_poly1305,
            inlateout("rdi") at => _,
            inlateout("r12") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    actual
}

/// Every byte of the frame as the frame writer leaves it, over a frame filled
/// with the poison first. Filling, calling and copying out are one block, so
/// nothing but the writer touches the window in between.
#[cfg(target_arch = "aarch64")]
fn capture_the_frame_writer(at: usize) -> [u8; FRAME] {
    let mut actual = [0xff_u8; FRAME];

    // SAFETY: the offset is inside the writer's frame and `actual` is as long
    // as it. x20 holds the destination across the call and the writer leaves
    // it alone. `bl` writes no stack, so reserving the frame again gives
    // exactly the writer's frame.
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
            writer = sym redoubt_poly1305_v2_dirty_frame_poly1305,
            inlateout("x0") at => _,
            inlateout("x20") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    actual
}

/// What the verifier answers when the only thing in the window is the byte left
/// at `at`: it ORs a word at a time, so the byte comes back in its place within
/// its word. Asserted exactly, because a window that slid reads bytes nobody
/// wrote, and "something was found" would take those for the byte.
fn only_the_byte_at(at: usize) -> u64 {
    u64::from(LEFT_BYTE) << (8 * (at % 8))
}

// ============================================================================
// redoubt_poly1305_v2_registers_are_zeroized
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
    use super::{POISON, redoubt_poly1305_v2_registers_are_zeroized};

    every_register!();
}

#[test]
fn test_the_list_names_as_many_registers_as_there_are_tests() {
    assert_eq!(GENERAL.len(), every_register::GENERAL_TESTS);
}

// ============================================================================
// redoubt_poly1305_v2_frame_is_zeroized_poly1305
// ============================================================================

/// The sweep is what shows the verifier reads the whole window, and an
/// off-by-one at either end shows here and nowhere else.
#[test]
fn test_a_byte_left_anywhere_in_the_frame_is_seen() {
    for at in 0..FRAME {
        // SAFETY: the offset is inside the frame the writer takes, and the
        // verifier reads the frame the writer gave back.
        let dirty = unsafe {
            redoubt_poly1305_v2_dirty_frame_poly1305(at);
            redoubt_poly1305_v2_frame_is_zeroized_poly1305()
        };

        assert_eq!(
            dirty,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}

#[test]
fn test_a_frame_written_and_emptied_reads_as_empty() {
    // SAFETY: the writer fills and empties the frame it takes, and the verifier
    // reads the frame it gave back.
    let dirty = unsafe {
        redoubt_poly1305_v2_clean_frame_poly1305();
        redoubt_poly1305_v2_frame_is_zeroized_poly1305()
    };

    // Assert zeroization!
    assert_eq!(dirty, 0, "a frame that was emptied reads as full");
}

/// An offset that expected zero would turn "the byte was found" into "nothing
/// was found", and the sweep would pass exactly where the byte went missing.
#[test]
fn test_no_offset_expects_an_empty_window() {
    for at in 0..FRAME {
        assert_ne!(only_the_byte_at(at), 0, "offset {at}");
    }
}

// ============================================================================
// redoubt_poly1305_v2_dirty_registers
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
// redoubt_poly1305_v2_dirty_frame_poly1305
// ============================================================================

/// Through the verifier, residue from an earlier call and the byte this one
/// wrote give the same answer, so this is the only test that catches a writer
/// that does not empty the frame first.
#[test]
fn test_dirty_frame_clears_every_byte_except_the_requested_one() {
    for at in 0..FRAME {
        let actual = capture_the_frame_writer(at);

        for (byte, &value) in actual.iter().enumerate() {
            assert_eq!(
                value,
                if byte == at { LEFT_BYTE } else { 0 },
                "requested byte {at}, captured byte {byte}",
            );
        }
    }
}
