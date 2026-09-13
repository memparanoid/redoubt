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
//! # What this does not say
//!
//! That the process is clean. Only that *this* routine erased *its own*
//! temporaries. Whatever somebody else left in another register is still
//! there, and so is the copy in the destination, which is the point of having
//! made it.
//!
//! # The zero that means nothing
//!
//! A capture that reads nothing reads zero, and so does a register that was
//! properly cleared. On `x86_64` the small paths never touch a vector
//! register at all, so the two are seeded with a value first: if the capture
//! were reading the wrong place, those seeds would come back and the
//! assertion would fail. On `aarch64` every path writes `v0`, so there is
//! nothing to seed.

#![cfg(all(unix, any(target_arch = "x86_64", target_arch = "aarch64")))]

// The routine is not part of this crate's public surface, so the test asks
// the linker for it by name. Naming the crate as well is what pulls its
// native library into the link.
use redoubt_mem as _;

unsafe extern "C" {
    fn redoubt_copy_bytes(src: *const u8, dst: *mut u8, bytes: usize);
}

/// Every register the routine puts copied bytes into, read at the return.
///
/// `x3` and the two halves of each of `v0-v3`, which is what the assembly
/// names as its payload.
#[cfg(target_arch = "aarch64")]
unsafe fn payload(src: *const u8, dst: *mut u8, bytes: usize) -> [u64; 9] {
    let (x3, v0_low, v0_high, v1_low, v1_high, v2_low, v2_high, v3_low, v3_high);

    // SAFETY: the call's own requirements, which the caller below meets. The
    // `umov`s read vector registers into general ones that are declared as
    // outputs, and the rest of the register file is declared clobbered.
    unsafe {
        core::arch::asm!(
            "bl {copy}",
            "umov x4, v0.d[0]",
            "umov x5, v0.d[1]",
            "umov x6, v1.d[0]",
            "umov x7, v1.d[1]",
            "umov x8, v2.d[0]",
            "umov x9, v2.d[1]",
            "umov x10, v3.d[0]",
            "umov x11, v3.d[1]",
            copy = sym redoubt_copy_bytes,
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
#[cfg(target_arch = "x86_64")]
unsafe fn payload(src: *const u8, dst: *mut u8, bytes: usize) -> [u64; 6] {
    let (rax, rcx, xmm0_low, xmm0_high, xmm1_low, xmm1_high);

    // SAFETY: the call's own requirements, which the caller below meets. The
    // two vector registers are seeded before the call so that a capture
    // reading the wrong place cannot pass by reading zero, and the rest of the
    // register file is declared clobbered.
    unsafe {
        core::arch::asm!(
            "pxor xmm0, xmm0",
            "pxor xmm1, xmm1",
            "call {copy}",
            "movq r8, xmm0",
            "psrldq xmm0, 8",
            "movq r9, xmm0",
            "movq r10, xmm1",
            "psrldq xmm1, 8",
            "movq r11, xmm1",
            copy = sym redoubt_copy_bytes,
            in("rdi") src,
            in("rsi") dst,
            in("rdx") bytes,
            lateout("rax") rax,
            lateout("rcx") rcx,
            lateout("r8") xmm0_low,
            lateout("r9") xmm0_high,
            lateout("r10") xmm1_low,
            lateout("r11") xmm1_high,
        );
    }

    [rax, rcx, xmm0_low, xmm0_high, xmm1_low, xmm1_high]
}

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
    for fill in [0xFF_u8, 0x97, 0x42] {
        let from = vec![fill; 8256];
        let mut into = vec![0_u8; from.len()];

        for of in (0..=1024).chain([2047, 2048, 2049, 4096, 8192]) {
            for at in [0_usize, 1, 15, 31, 63] {
                // SAFETY: two different allocations, both `8256` long, and
                // `at + of` never reaches that.
                let held = unsafe { payload(from.as_ptr().add(at), into.as_mut_ptr().add(at), of) };

                assert!(
                    held.iter().all(|word| *word == 0),
                    "fill {fill:#x}, {of} bytes at {at}: {held:x?}",
                );

                assert_eq!(&from[at..at + of], &into[at..at + of], "{of} bytes at {at}");
            }
        }
    }
}
