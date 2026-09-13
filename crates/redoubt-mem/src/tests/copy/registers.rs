// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That the copy leaves none of the bytes it moved in a register.
//!
//! This is the whole reason the crate exists, and it is the one claim that
//! cannot be checked by looking at the destination.
//!
//! # Why the capture is inside the asm block
//!
//! A register is read here before any Rust runs, in the same inline assembly
//! that makes the call. Anything else — a wrapper, a `let`, a function that
//! returns the values — is code the compiler is free to put between the return
//! and the reading, and a register does not survive that. It would not be a
//! weaker test, it would be a test of something else: whether the register
//! survived the trip back, not whether the routine cleared it.
//!
//! So the answer is carried out in registers the routine does not use, which
//! is why the capture reads into `r8-r11` on `x86_64` and `x4-x11` on
//! `aarch64`.
//!
//! # The zero that means nothing
//!
//! A capture that reads nothing reads zero, and so does a register that was
//! properly cleared, so a zero on its own says neither. Every payload register
//! is seeded with ones before the call, and a routine that returns without
//! touching anything is run through the same capture: it must come back
//! holding every seed. Only then does the zero beside it mean anything.
//!
//! What a word may come back as is therefore zero **or** the seed. A copy
//! short enough never to reach the vector path put nothing in one, and the
//! promise is only about temporaries the routine used. Which is why no fill
//! below may be `0xFF`: a vector full of that payload reads the same as a
//! vector nobody touched.
//!
//! # What this does not say
//!
//! That the process is clean. Only that *this* routine erased *its own*
//! temporaries. Whatever somebody else left in another register is still
//! there, and so is the copy in the destination, which is the point of having
//! made it.

#![cfg(all(unix, any(target_arch = "x86_64", target_arch = "aarch64")))]

use std::vec;

// The routine is not part of this crate's public surface, so the test asks the
// linker for it by name.
unsafe extern "C" {
    fn redoubt_copy_bytes(src: *const u8, dst: *mut u8, bytes: usize);
}

type CopyBytes = unsafe extern "C" fn(*const u8, *mut u8, usize);

/// A routine with the same signature that does nothing at all.
///
/// Naked, so that the compiler emits no prologue: every register the capture
/// seeded is still seeded when it returns.
#[unsafe(naked)]
unsafe extern "C" fn leaves_everything(_: *const u8, _: *mut u8, _: usize) {
    core::arch::naked_asm!("ret");
}

/// A routine that copies sixteen bytes through a vector register and returns
/// without erasing it.
///
/// The other half of the calibration. `leaves_everything` says the capture can
/// see a register nobody wrote; this says it can see one holding what was
/// copied, which is the thing the real test asserts the absence of. Without
/// it, an assertion that can never fail would read exactly like one that
/// always passes.
///
/// # Safety
///
/// `src` readable and `dst` writable for at least sixteen bytes, and disjoint.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn leaves_the_payload(_: *const u8, _: *mut u8, _: usize) {
    core::arch::naked_asm!("movdqu xmm0, [rdi]", "movdqu [rsi], xmm0", "ret");
}

/// The same, through `v0`.
///
/// # Safety
///
/// As above.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn leaves_the_payload(_: *const u8, _: *mut u8, _: usize) {
    core::arch::naked_asm!("ldr q0, [x0]", "str q0, [x1]", "ret");
}

/// Every register the routine puts copied bytes into, seeded with ones and
/// read at the return.
///
/// `x3` and the two halves of each of `v0-v3`, which is what the assembly
/// names as its payload.
///
/// # Safety
///
/// `f` must follow the C ABI and the same contract as the routine under test:
/// `src` readable and `dst` writable for `bytes`, and the ranges disjoint.
#[cfg(target_arch = "aarch64")]
unsafe fn payload(f: CopyBytes, src: *const u8, dst: *mut u8, bytes: usize) -> [u64; 9] {
    let (x3, v0_low, v0_high, v1_low, v1_high, v2_low, v2_high, v3_low, v3_high);

    // SAFETY: the caller's contract. The `umov`s read vector registers into
    // general ones that are declared as outputs, and the rest of the register
    // file is declared clobbered.
    unsafe {
        core::arch::asm!(
            "mov x3, -1",
            "movi v0.16b, #255",
            "movi v1.16b, #255",
            "movi v2.16b, #255",
            "movi v3.16b, #255",
            "blr x16",
            "umov x4, v0.d[0]",
            "umov x5, v0.d[1]",
            "umov x6, v1.d[0]",
            "umov x7, v1.d[1]",
            "umov x8, v2.d[0]",
            "umov x9, v2.d[1]",
            "umov x10, v3.d[0]",
            "umov x11, v3.d[1]",
            in("x16") f,
            in("x0") src,
            in("x1") dst,
            in("x2") bytes,
            lateout("x3") x3,
            lateout("x4") v0_low,
            lateout("x5") v0_high,
            lateout("x6") v1_low,
            lateout("x7") v1_high,
            lateout("x8") v2_low,
            lateout("x9") v2_high,
            lateout("x10") v3_low,
            lateout("x11") v3_high,
            clobber_abi("C"),
        );
    }

    [
        x3, v0_low, v0_high, v1_low, v1_high, v2_low, v2_high, v3_low, v3_high,
    ]
}

/// The same: `rax`, `rcx`, and the two halves of each of `xmm0` and `xmm1`.
///
/// # Safety
///
/// As above.
#[cfg(target_arch = "x86_64")]
unsafe fn payload(f: CopyBytes, src: *const u8, dst: *mut u8, bytes: usize) -> [u64; 6] {
    let (rax, rcx, xmm0_low, xmm0_high, xmm1_low, xmm1_high);

    // SAFETY: the caller's contract, plus: `r12` is callee-saved under SysV,
    // so it still holds the routine's address when the call is made.
    unsafe {
        core::arch::asm!(
            "mov rax, -1",
            "mov rcx, -1",
            "pcmpeqd xmm0, xmm0",
            "pcmpeqd xmm1, xmm1",
            "call r12",
            "movq r8, xmm0",
            "psrldq xmm0, 8",
            "movq r9, xmm0",
            "movq r10, xmm1",
            "psrldq xmm1, 8",
            "movq r11, xmm1",
            in("r12") f,
            in("rdi") src,
            in("rsi") dst,
            in("rdx") bytes,
            lateout("rax") rax,
            lateout("rcx") rcx,
            lateout("r8") xmm0_low,
            lateout("r9") xmm0_high,
            lateout("r10") xmm1_low,
            lateout("r11") xmm1_high,
            clobber_abi("C"),
        );
    }

    [rax, rcx, xmm0_low, xmm0_high, xmm1_low, xmm1_high]
}

// ============================================================================
// The control
// ============================================================================

/// The capture reports the seeds when the routine leaves them alone.
///
/// Every zero the test below reports is worth exactly what this one is worth:
/// a capture that read zeros no matter what would call every routine clean,
/// this one included.
#[test]
fn test_the_capture_reports_registers_a_routine_left_untouched() {
    let from = [0xFF_u8; 64];
    let mut into = [0_u8; 64];

    // SAFETY: two separate allocations of 64 bytes, and a routine that touches
    // neither.
    let held = unsafe { payload(leaves_everything, from.as_ptr(), into.as_mut_ptr(), 64) };

    assert!(
        held.iter().all(|word| *word == u64::MAX),
        "the capture cannot see what a routine left: {held:x?}",
    );

    assert!(
        into.iter().all(|byte| *byte == 0),
        "a routine that returns copied nothing",
    );
}

/// The capture reports the copied byte when a routine leaves it in a register.
///
/// The assertion below is that no captured byte is the one that was copied.
/// This is what says that assertion can fail at all: the same capture, the
/// same check, against a routine that deliberately leaves the payload where
/// the real one erases it.
#[test]
fn test_the_capture_reports_a_byte_a_routine_left_in_a_register() {
    const FILL: u8 = 0x97;

    let from = [FILL; 64];
    let mut into = [0_u8; 64];

    // SAFETY: two separate allocations of 64 bytes, and a routine that reads
    // and writes sixteen of each.
    let held = unsafe { payload(leaves_the_payload, from.as_ptr(), into.as_mut_ptr(), 64) };

    assert!(
        held.iter().any(|word| word.to_ne_bytes().contains(&FILL)),
        "the capture cannot see a copied byte left in a register: {held:x?}",
    );
}

// ============================================================================
// redoubt_copy_bytes
// ============================================================================

/// Nothing of what was copied is in a register when the routine returns.
///
/// Every length that reaches a different path, and several alignments of each,
/// because the tail a length lands in depends on where it started.
///
/// The source is filled with one repeated byte on purpose: a register holding
/// any part of it is a register holding that byte, so a residue of a single
/// byte in a corner of a vector register is as loud as a whole one.
#[test]
fn test_no_register_holds_what_was_copied() {
    // Neither `0x00` nor `0xFF`: those are what an erased register and an
    // untouched one hold, so payload made of either would read as innocent.
    for fill in [0x97_u8, 0x42, 0x5A] {
        let from = vec![fill; 8256];
        let mut into = vec![0_u8; from.len()];

        for of in (0..=1024).chain([2047, 2048, 2049, 4096, 8192]) {
            for at in [0_usize, 1, 15, 31, 63] {
                // SAFETY: two different allocations, both `8256` long, and
                // `at + of` never reaches that.
                let held = unsafe {
                    payload(
                        redoubt_copy_bytes,
                        from.as_ptr().add(at),
                        into.as_mut_ptr().add(at),
                        of,
                    )
                };

                // Not "every register is zero". The promise is about the bytes
                // that were copied, and a register the routine never wrote —
                // every vector register, for a copy too short to reach them —
                // is as clean as one it erased.
                assert!(
                    held.iter()
                        .all(|word| word.to_ne_bytes().iter().all(|byte| *byte != fill)),
                    "fill {fill:#x}, {of} bytes at {at}: {held:x?}",
                );

                assert_eq!(&from[at..at + of], &into[at..at + of], "{of} bytes at {at}");
            }
        }
    }
}
