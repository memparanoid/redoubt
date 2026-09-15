// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the comparison leaves behind, asked of the verifier in `probes`.
//!
//! Its own tests live there; here it is used and not measured. What is measured
//! here is the routine, and only what it left: what it answers is settled in
//! `backend.rs`, against both implementations.
//!
//! Three cases, the two negatives first and the real one last, because the
//! negatives are what make it mean anything.
//!
//! The dirtying goes first. The selected routine and the verifier then run in
//! one assembly block, so Rust cannot insert work before the measurement.
//!
//! There is no frame half of this. Nothing in the file under test takes one —
//! `sub rsp` and `push` appear nowhere in it — and a spill that arrived would
//! have arrived by somebody typing it, which a diff shows.
//!
//! These are not claims about kernel signal frames, swap, dumps, or the input
//! and output the caller owns.

mod probes;

use rstest::rstest;

// The assembly, in the order the file declares it: the one entry point the
// backend calls, then the probe, which nothing in production calls.
unsafe extern "C" {
    fn redoubt_ct_eq(a: *const u8, b: *const u8, len: usize, out: *mut u8);

    // The probe, last and apart: what asks first, then what is asked about.
    fn redoubt_ct_registers_are_zeroized() -> u64;
    fn redoubt_ct_dirty_registers();
}

/// A negative control with the same arguments as the routine it replaces.
///
/// The tail branch keeps the caller's stack pointer and return address. A
/// regular Rust wrapper could take a frame or change the registers on return,
/// making the residue belong to the wrapper instead of the helper.
///
/// It never dereferences its arguments, which is why the real routine's
/// preconditions do not reach it.
#[unsafe(naked)]
unsafe extern "C" fn dirty_registers(_a: *const u8, _b: *const u8, _len: usize, _out: *mut u8) {
    #[cfg(target_arch = "x86_64")]
    core::arch::naked_asm!("jmp {target}", target = sym redoubt_ct_dirty_registers);

    #[cfg(target_arch = "aarch64")]
    core::arch::naked_asm!("b {target}", target = sym redoubt_ct_dirty_registers);
}

/// A control that answers without touching anything, so the real case cannot
/// pass by the machine having been clean all along.
///
/// The routine writes one byte through its fourth argument; this writes the
/// same byte and returns, leaving every register the caller filled.
#[unsafe(naked)]
unsafe extern "C" fn untouched(_a: *const u8, _b: *const u8, _len: usize, _out: *mut u8) {
    #[cfg(target_arch = "x86_64")]
    core::arch::naked_asm!("mov byte ptr [rcx], 1", "ret");

    #[cfg(target_arch = "aarch64")]
    core::arch::naked_asm!("mov w4, #1", "strb w4, [x3]", "ret");
}

/// Which residue the case deliberately leaves, or none for the real call.
#[derive(Clone, Copy)]
enum Left {
    Registers,
    Nothing,
}

type CtEq = unsafe extern "C" fn(*const u8, *const u8, usize, *mut u8);

#[rstest]
#[case::registers_left_full(dirty_registers as CtEq, Left::Registers)]
#[case::nothing_ran(untouched as CtEq, Left::Registers)]
#[case::real(redoubt_ct_eq as CtEq, Left::Nothing)]
fn test_ct_eq_leaves_the_residue_its_case_declares(#[case] routine: CtEq, #[case] left: Left) {
    // All cases use this indirect call site, including under release/LTO.
    // The controls exercise this caller; they do not certify other callers.
    let routine = core::hint::black_box(routine);
    let a = [0x5au8; 16];
    let b = a;
    let mut same = 0u8;
    let registers: u64;

    // SAFETY: both pointers are to sixteen readable bytes, the length says so,
    // and `same` is one writable byte that neither of them overlaps. The
    // verifier takes no argument and answers in the return register.
    unsafe {
        redoubt_ct_dirty_registers();

        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "call r11",
            "call {verifier}",
            verifier = sym redoubt_ct_registers_are_zeroized,
            inlateout("r11") routine => _,
            inlateout("rdi") a.as_ptr() => _,
            inlateout("rsi") b.as_ptr() => _,
            inlateout("rdx") a.len() => _,
            inlateout("rcx") &raw mut same => _,
            lateout("rax") registers,
            clobber_abi("C"),
        );

        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "blr x16",
            "bl {verifier}",
            verifier = sym redoubt_ct_registers_are_zeroized,
            inlateout("x16") routine => _,
            inlateout("x0") a.as_ptr() => registers,
            inlateout("x1") b.as_ptr() => _,
            inlateout("x2") a.len() => _,
            inlateout("x3") &raw mut same => _,
            clobber_abi("C"),
        );
    }

    match left {
        Left::Registers => {
            assert_ne!(
                registers, 0,
                "registers the replacement left full read as empty"
            );
        }
        Left::Nothing => {
            // Assert zeroization!
            assert_eq!(registers, 0, "the registers after the real routine");

            // Only the real routine answers. The two above are here for what
            // they leave behind, and neither computes anything to leave.
            assert_eq!(same, 1, "the two equal runs read as different");
        }
    }
}
