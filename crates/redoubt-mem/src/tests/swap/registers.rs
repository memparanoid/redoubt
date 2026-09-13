// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That the swap leaves none of the bytes it moved in the registers it moved
//! them through.
//!
//! # Why the capture is in the same `asm!` block as the call
//!
//! The registers being asked about are caller-saved, so the first instruction
//! the compiler emits after the call is free to overwrite them. No Rust runs
//! between the two here — the snapshot is written to memory by the same block
//! that made the call, which is the only way the answer is about the routine
//! and not about what the test did next.
//!
//! # What it covers, and what it does not
//!
//! The ten words this routine's own documentation names as its temporaries:
//! `rax`, `rcx` and the low lanes of `xmm0-3` on x86_64; `x3`, `x4` and
//! `v0-v3` on aarch64. It says nothing about residue somebody else left, about
//! what the operating system saved on a signal, or about anything
//! microarchitectural. `forensics.rs` asks the wider question of the whole
//! process; this one asks a narrow one exactly.
//!
//! It calls the assembly symbol rather than the Rust wrapper, which is what
//! lets a length of zero be asked about at all: the wrapper skips the call.

#![cfg(all(unix, any(target_arch = "x86_64", target_arch = "aarch64")))]

use std::vec;

type Swap = unsafe extern "C" fn(*mut u8, *mut u8, usize);

unsafe extern "C" {
    fn redoubt_mem_swap(a: *mut u8, b: *mut u8, n: usize);
}

/// A routine with the same signature that does nothing at all.
///
/// Naked, so that the compiler emits no prologue: every register the capture
/// seeded is still seeded when it returns. That is what makes it a control —
/// if the capture reported zeros for this, it would be reporting zeros for
/// everything, and the real measurement would mean nothing.
#[unsafe(naked)]
unsafe extern "C" fn leaves_everything(_: *mut u8, _: *mut u8, _: usize) {
    core::arch::naked_asm!("ret");
}

/// Every payload register, seeded with ones, read back the instant `f`
/// returns.
///
/// # Safety
///
/// `f` must follow the C ABI and the same contract as the routine under test:
/// `a` and `b` valid for `n` bytes, and not overlapping.
#[cfg(target_arch = "x86_64")]
unsafe fn capture(f: Swap, a: *mut u8, b: *mut u8, n: usize) -> [u64; 10] {
    let mut vectors = [0_u64; 8];
    let (rax, rcx);

    // SAFETY: the caller's contract, plus: `r12` is callee-saved under SysV,
    // so it still points at `vectors` when the call returns.
    unsafe {
        core::arch::asm!(
            "mov rax, -1",
            "mov rcx, -1",
            "pcmpeqd xmm0, xmm0",
            "pcmpeqd xmm1, xmm1",
            "pcmpeqd xmm2, xmm2",
            "pcmpeqd xmm3, xmm3",
            "call r11",
            "movdqu [r12], xmm0",
            "movdqu [r12 + 16], xmm1",
            "movdqu [r12 + 32], xmm2",
            "movdqu [r12 + 48], xmm3",
            in("r11") f,
            in("r12") vectors.as_mut_ptr(),
            in("rdi") a,
            in("rsi") b,
            in("rdx") n,
            lateout("rax") rax,
            lateout("rcx") rcx,
            clobber_abi("C"),
        );
    }

    let mut seen = [0; 10];

    seen[..2].copy_from_slice(&[rax, rcx]);
    seen[2..].copy_from_slice(&vectors);

    seen
}

/// The same, for the registers this architecture's routine uses.
///
/// # Safety
///
/// As above.
#[cfg(target_arch = "aarch64")]
unsafe fn capture(f: Swap, a: *mut u8, b: *mut u8, n: usize) -> [u64; 10] {
    let mut vectors = [0_u64; 8];
    let (x3, x4);

    // SAFETY: the caller's contract, plus: `x20` is callee-saved, so it still
    // points at `vectors` when the call returns. `x19` would do as well and is
    // reserved by LLVM on this target, which refuses it as an operand.
    unsafe {
        core::arch::asm!(
            "mov x3, -1",
            "mov x4, -1",
            "movi v0.16b, #255",
            "movi v1.16b, #255",
            "movi v2.16b, #255",
            "movi v3.16b, #255",
            "blr x16",
            "stp q0, q1, [x20]",
            "stp q2, q3, [x20, #32]",
            in("x16") f,
            in("x20") vectors.as_mut_ptr(),
            in("x0") a,
            in("x1") b,
            in("x2") n,
            lateout("x3") x3,
            lateout("x4") x4,
            clobber_abi("C"),
        );
    }

    let mut seen = [0; 10];

    seen[..2].copy_from_slice(&[x3, x4]);
    seen[2..].copy_from_slice(&vectors);

    seen
}

// ============================================================================
// The control
// ============================================================================

/// The capture reports dirt when the registers are dirty.
///
/// Every zero the test below reports is worth exactly what this one is worth:
/// a capture that read zeros no matter what would call every routine clean,
/// this one included.
#[test]
fn test_the_capture_reports_registers_a_routine_left_untouched() {
    let mut a = [1; 64];
    let mut b = [2; 64];

    // SAFETY: two separate arrays of 64 bytes, and a routine that touches
    // neither.
    let seen = unsafe { capture(leaves_everything, a.as_mut_ptr(), b.as_mut_ptr(), 64) };

    assert_eq!(seen, [u64::MAX; 10], "the capture cannot see dirt");

    assert_eq!(a, [1; 64], "a routine that returns moved nothing");
    assert_eq!(b, [2; 64]);
}

// ============================================================================
// redoubt_mem_swap
// ============================================================================

/// Nothing left in any payload register, on every path through the routine.
///
/// The lengths walk every branch the assembly has — each bit of the tail, the
/// loop, and the boundaries either side of the sizes where a length is easy to
/// get wrong. The offsets vary because the erasure is at the end and the path
/// to it is not, and the byte values differ between the two runs so that a
/// register left holding one side is not mistaken for a register left holding
/// the other.
///
/// The exchange itself is asserted alongside, so a routine that erased its
/// registers by not doing the work would fail here rather than pass.
#[test]
fn test_swap_leaves_no_payload_register_holding_either_side() {
    for (left, right) in [(0xff, 0x97), (0x42, 0xbd)] {
        for n in (0..=1024).chain([2047, 2048, 2049, 4095, 4096, 4097, 8192]) {
            for (offset_a, offset_b) in [(0, 0), (1, 63), (63, 1), (15, 31)] {
                let mut a = vec![left; n + 128];
                let mut b = vec![right; n + 128];

                // SAFETY: `n` bytes past each offset fit in buffers of
                // `n + 128`, and the two are separate allocations.
                let seen = unsafe {
                    capture(
                        redoubt_mem_swap,
                        a.as_mut_ptr().add(offset_a),
                        b.as_mut_ptr().add(offset_b),
                        n,
                    )
                };

                assert_eq!(seen, [0; 10], "n={n} offsets={offset_a},{offset_b}");

                assert!(a[offset_a..offset_a + n].iter().all(|&v| v == right));
                assert!(b[offset_b..offset_b + n].iter().all(|&v| v == left));

                assert!(
                    a[..offset_a]
                        .iter()
                        .chain(&a[offset_a + n..])
                        .all(|&v| v == left)
                );

                assert!(
                    b[..offset_b]
                        .iter()
                        .chain(&b[offset_b + n..])
                        .all(|&v| v == right)
                );
            }
        }
    }
}
