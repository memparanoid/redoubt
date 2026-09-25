// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a measurement has to be shaped like for its answer to be about the
//! operation.
//!
//! # The two places a secret is left
//!
//! **Registers.** A register is in no mapping, so nothing that reads memory
//! has ever been able to see one. A sweep that finds nothing there has not
//! looked.
//!
//! **The stack the operation used.** Those frames are readable where they are,
//! and they are not durable: a call made afterwards writes exactly there, and
//! a secret of a few dozen bytes goes under it whole. The photograph then
//! reports a clean process, and it reports it just as cleanly for an operation
//! that wiped nothing. That is the failure this file exists for — it was found
//! in a crate above, where a test went on passing against a zeroization that
//! had been commented out.
//!
//! [`freeze!`] answers both at once, and this file asserts each half against
//! a control that says the sweep could not have found it on its own.
//!
//! # The shape
//!
//! ```text
//! forensics!({
//!     operation();        // the only thing that touches the secret
//!     freeze!();         // the registers, and the stack, out of reach
//!     cleanup();          // anything at all
//! });
//!
//! let report_after = watch.snapshot()?;
//! ```
//!
//! What is left of the rule is one line long: nothing goes between the
//! operation and the capture.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place the secret could be. `nextest`, not `cargo test`.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use redoubt_forensics::{AnyError, Forensics, forensics, freeze, pick_spiller};

mod support;

use support::helpers::alone;

/// Thirty-two distinct bytes: no value repeats, so a run that extends did not
/// extend by luck.
///
/// A `const`, so it lives in a mapping nothing may write — and the sweep reads
/// only writable ones, so the original is never found as a copy of itself.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// Sixteen distinct bytes, for the half of this file that is about registers.
///
/// Sixteen and not thirty-two because a register is as wide as it is. One
/// vector register holds this whole, and the room gives each of them a slot of
/// its own with sixty-four bytes between them — so a secret wider than one
/// register lands in two slots that are not next to each other, and a search
/// for the whole of it finds nothing however faithfully it was captured.
const NARROW: [u8; 16] = [
    0x3D, 0xB2, 0x7F, 0x08, 0xE4, 0x59, 0xAC, 0x16, 0xC7, 0x2A, 0x93, 0xF1, 0x6B, 0xD0, 0x45, 0x8E,
];

/// How much a cleanup allocates, so that freeing it is a real call and not
/// something the compiler folds away.
const WASTE: usize = 1024;

/// A needle, built from its last byte to its first.
///
/// Never turned around in this process: the forward bytes must not exist here
/// even for as long as it would take to reverse them.
fn backwards(of: &[u8]) -> Vec<u8> {
    of.iter().rev().copied().collect()
}

/// A secret into somewhere the caller owns, one byte at a time through a
/// pointer.
///
/// Not an assignment: `held = SECRET` is whatever move the compiler decides to
/// emit, and on `aarch64` it emitted one that left a copy the wipe below could
/// not reach — which turned a test of the wipe into a test of the copy.
/// Through a pointer there is one copy, and it is at the address the wipe is
/// given.
fn giving(into: &mut [u8], from: &[u8]) {
    for (at, byte) in from.iter().enumerate() {
        // SAFETY: `at` indexes a destination at least as wide as the source,
        // which is every caller here.
        unsafe { into.as_mut_ptr().add(at).write_volatile(*byte) };
    }
}

/// It out of there again, the same way.
fn taking(from: &mut [u8]) {
    for at in 0..from.len() {
        // SAFETY: as above.
        unsafe { from.as_mut_ptr().add(at).write_volatile(0) };
    }
}

/// Sixteen bytes into a vector register and out of the memory they came from,
/// with nothing in between.
///
/// Both halves are one `asm!` block on purpose. A load in one statement and a
/// wipe in the next is a wipe the compiler may reorder, vectorize through the
/// register just loaded, or turn into a call — and any of those makes the test
/// about something else. Inside one block there is nowhere to put anything.
///
/// Afterwards the sixteen bytes are in `xmm0` or `v0` and nowhere in memory at
/// all, which is what the two tests below are both about: one that a capture
/// finds them, and one that nothing else can.
#[inline(always)]
fn into_a_register(from: &mut [u8; NARROW.len()]) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: sixteen bytes read and sixteen written at a pointer to a
    // destination of exactly that width, unaligned on both sides, and the two
    // registers written are declared.
    unsafe {
        core::arch::asm!(
            "movdqu xmm0, [{at}]",
            "pxor xmm1, xmm1",
            "movdqu [{at}], xmm1",
            at = in(reg) from.as_mut_ptr(),
            out("xmm0") _,
            out("xmm1") _,
        );
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: as above.
    unsafe {
        core::arch::asm!(
            "ldr q0, [{at}]",
            "movi v1.16b, #0",
            "str q1, [{at}]",
            at = in(reg) from.as_mut_ptr(),
            out("v0") _,
            out("v1") _,
        );
    }
}

/// An operation that leaves the secret in the frame it used.
///
/// Not inlined, so the frame is one the machine makes and leaves; folded into
/// its caller there would be no frame to leave and nothing to find.
#[inline(never)]
fn a_frame_left_full() {
    let mut held = [0_u8; SECRET.len()];

    giving(&mut held, &SECRET);

    core::hint::black_box(&held);
}

/// The same operation, emptying the frame before it leaves it.
#[inline(never)]
fn a_frame_emptied() {
    let mut held = [0_u8; SECRET.len()];

    giving(&mut held, &SECRET);

    core::hint::black_box(&held);

    taking(&mut held);

    core::hint::black_box(&held);
}

/// Said out loud when the machine has no register to hide a secret in.
///
/// The pair below asks whether the capture reaches a place the sweep cannot,
/// and on a machine with no such place there is nothing to ask. What there
/// must not be is a green that read nothing looking like a green that read
/// everything.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! wide {
    () => {
        if !has_a_wide_register() {
            eprintln!(
                "skipped: this machine has no register the compiler is obliged \
                 to leave alone, so the capture has nothing here to reach."
            );

            return Ok(());
        }
    };
}

/// Sixteen bytes nothing else in this process is holding.
///
/// Sixteen and not thirty-two, because on one of the two architectures below
/// the part of the register the compiler leaves alone begins at a hundred and
/// twenty-eight bits, and a needle that straddles that line is half in a place
/// anything may overwrite.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const HELD: [u8; 16] = [
    0x9E, 0x41, 0xD7, 0x2B, 0x60, 0xFA, 0x35, 0xC8, 0x1D, 0xB4, 0x7F, 0x02, 0xE6, 0x59, 0xA3, 0x18,
];

/// Whether this machine has a register the compiler is obliged to leave alone.
///
/// Not a property of the code. `zmm16-31` exist where there is `avx512`, and
/// above the first hundred and twenty-eight bits of `z0-z31` exists where
/// there is SVE wide enough to have an above — a machine whose vector length
/// is sixteen bytes has nothing past what NEON already uses.
#[cfg(target_arch = "x86_64")]
fn has_a_wide_register() -> bool {
    std::arch::is_x86_feature_detected!("avx512f")
}

/// Whether this machine's SVE registers reach past what NEON uses.
#[cfg(target_arch = "aarch64")]
fn has_a_wide_register() -> bool {
    std::arch::is_aarch64_feature_detected!("sve") && vector_length() > 16
}

/// How many bytes wide this machine's SVE registers are.
#[cfg(target_arch = "aarch64")]
fn vector_length() -> usize {
    let bytes: u64;

    // SAFETY: reads the vector length into a register of the compiler's
    // choosing and touches nothing else. Guarded by the feature check above,
    // which is why this is never reached on a machine without SVE.
    unsafe {
        core::arch::asm!(
            ".arch_extension sve",
            "rdvl {bytes}, #1",
            ".arch_extension nosve",
            bytes = out(reg) bytes,
            options(nomem, nostack),
        );
    }

    bytes as usize
}

/// The secret put in one wide register, where only the capture can reach it.
///
/// The seeding is in the measured block and the capture is the macro's, so
/// between the two the compiler may put anything in a register it is entitled
/// to use. These are the ones it is not: `zmm16-31` are reachable only by
/// `avx512` encodings, which nothing here compiles. A value left there is
/// still there when the macro looks — which is the case the capture exists
/// for, since a wide `memcpy` of a key leaves it in exactly these and nothing
/// in the process ever clears them.
///
/// The buffer is as wide as the load, because the load is what decides: this
/// one reads sixty-four bytes whatever the secret's length.
///
/// It is erased before the block ends, so at the moment of the photograph the
/// register is the only place the secret is.
#[cfg(target_arch = "x86_64")]
macro_rules! only_in_a_wide_register {
    ($load:tt, $declared:tt) => {{
        let mut from = [0_u8; 64];

        // Through the copy whose registers are probed: one the compiler emits
        // passes the secret through a vector register of its choosing, and the
        // capture then finds it there rather than in the one named.
        // SAFETY: `HELD` fits at the front of `from`, and the two do not overlap.
        unsafe {
            redoubt_mem_core::copy_nonoverlapping(HELD.as_ptr(), from.as_mut_ptr(), HELD.len())
        };

        // SAFETY: one write to one vector register, declared, reading the
        // sixty-four bytes the buffer has and no more. The load is unaligned.
        unsafe {
            core::arch::asm!(
                concat!("vmovdqu64 ", $load, ", [{from}]"),
                from = in(reg) from.as_ptr(),
                out($declared) _,
            );
        }

        erase(&mut from);
    }};
}

/// The secret put in the far end of one `z`, where only the capture can reach
/// it.
///
/// Past its first hundred and twenty-eight bits. The low half is a `v`, which
/// ordinary compiled code writes whenever it feels like it; everything above is
/// reachable by SVE encodings alone, and nothing here compiles any. So the
/// secret goes at sixteen bytes in, and what sits below it is padding whose
/// fate nobody cares about.
///
/// `ldr` and not a predicated load: it moves the whole register, so the buffer
/// is the vector length and there is no predicate register to name — and which
/// predicates Rust will hand out is a question with a different answer on
/// every toolchain.
#[cfg(target_arch = "aarch64")]
macro_rules! only_in_a_wide_register {
    ($load:tt, $declared:tt) => {{
        let wide = vector_length();
        let mut from = vec![0_u8; wide];

        // Through the copy whose registers are probed: one the compiler emits
        // passes the secret through a vector register of its choosing, and the
        // capture then finds it there rather than in the one named.
        // SAFETY: `HELD` fits sixteen bytes into `from`, and the two do not
        // overlap.
        unsafe {
            redoubt_mem_core::copy_nonoverlapping(
                HELD.as_ptr(),
                from.as_mut_ptr().add(16),
                HELD.len(),
            );
        };

        // SAFETY: one write to one vector register, declared as the NEON half
        // that Rust can name, reading exactly the vector length the buffer was
        // made from.
        unsafe {
            core::arch::asm!(
                ".arch_extension sve",
                concat!("ldr ", $load, ", [{from}]"),
                ".arch_extension nosve",
                from = in(reg) from.as_ptr(),
                out($declared) _,
            );
        }

        erase(&mut from);
    }};
}

/// The first wide register, for a test that asks about the shape and not about
/// which register.
#[cfg(target_arch = "x86_64")]
macro_rules! a_wide_register {
    () => {
        only_in_a_wide_register!("zmm16", "zmm16")
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! a_wide_register {
    () => {
        only_in_a_wide_register!("z16", "v16")
    };
}

/// The buffer, gone before the block ends.
///
/// Volatile, because nothing reads these bytes afterwards and that is exactly
/// the write an optimiser may delete. If it did, the buffer would be a second
/// place the secret is, and the pair below would agree for a reason that has
/// nothing to do with the capture.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn erase(from: &mut [u8]) {
    for byte in from.iter_mut() {
        // SAFETY: a `&mut u8` is valid to write through, volatile or not.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}
// ============================================================================
// The registers
// ============================================================================

/// The capture finds a secret that is in a register and nowhere else.
///
/// The memory it came from is emptied in the same instruction stream that
/// loaded it, so at the moment of the capture the only copy in this process is
/// in `xmm0` or `v0`. Finding it afterwards means the capture wrote the
/// register file somewhere a sweep reaches, which is the whole of what the
/// register half is for.
#[test]
fn test_the_capture_finds_a_secret_that_is_only_in_a_register() -> Result<(), AnyError> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&NARROW))?;

    let mut held = [0_u8; NARROW.len()];

    giving(&mut held, &NARROW);

    forensics!({
        into_a_register(&mut held);
        freeze!();
    });

    let report = watch.snapshot()?;

    println!();
    report.summary("only in a register");
    println!();

    assert!(
        report.found,
        "a value the capture was the only way to reach did not turn up, so the \
         register half of every measurement in this workspace is reading \
         nothing: {report}"
    );

    Ok(())
}

/// The same value, with no capture, is nowhere the sweep can reach.
///
/// The control, and what makes the test above say anything. A sweep that could
/// find a register's contents on its own would pass that one whether or not
/// the capture ever ran — and a sweep that finds this one is finding a copy in
/// memory that the load was supposed to have left nowhere.
#[test]
fn test_a_register_is_out_of_reach_without_the_capture() -> Result<(), AnyError> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&NARROW))?;

    let mut held = [0_u8; NARROW.len()];

    giving(&mut held, &NARROW);

    into_a_register(&mut held);

    let report = watch.snapshot()?;

    println!();
    report.summary("a register, uncaptured");
    println!();

    assert!(
        !report.found,
        "the sweep reached a value that is only in a register, so it is \
         reading a copy in memory that nobody meant to leave: {report}"
    );

    Ok(())
}

/// A secret in one wide register, found through the whole path a consumer
/// takes, and the same block with the capture taken out, which must find
/// nothing.
///
/// `xmm0` may be overwritten between the operation and the capture, so the
/// pair for it is true and a little lucky. `zmm16-31` and the far end of
/// `z0-z31` are what no compiler emits unless it was asked to, which makes
/// these the same claim without the luck, one register at a time.
///
/// They are also the pairs that go red if the capture is deleted. Every other
/// test here leaves its secret in memory as well, and would stay green.
macro_rules! test_a_wide_register_is_reached {
    ($found:ident, $unseen:ident, $load:tt, $declared:tt) => {
        #[test]
        fn $found() -> Result<(), AnyError> {
            alone!();

            wide!();

            let mut watch = Forensics::watching(&backwards(&HELD))?;

            forensics!({
                only_in_a_wide_register!($load, $declared);

                freeze!();
            });

            let with = watch.snapshot()?;

            assert!(
                with.found,
                concat!(
                    "the secret was in ",
                    $load,
                    " and the photograph did not have it, so the capture did \
                     not reach it: {}"
                ),
                with,
            );

            Ok(())
        }

        #[test]
        fn $unseen() -> Result<(), AnyError> {
            alone!();

            wide!();

            let mut watch = Forensics::watching(&backwards(&HELD))?;

            forensics!({
                only_in_a_wide_register!($load, $declared);
            });

            let without = watch.snapshot()?;

            assert!(
                !without.found,
                concat!(
                    "the secret in ",
                    $load,
                    " was reachable with no capture taken, so finding it with \
                     one proves nothing about the capture: {}"
                ),
                without,
            );

            Ok(())
        }
    };
}

#[cfg(target_arch = "x86_64")]
mod every_wide_register {
    use super::*;

    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm16,
        test_zmm16_is_out_of_reach_without_the_capture,
        "zmm16",
        "zmm16"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm17,
        test_zmm17_is_out_of_reach_without_the_capture,
        "zmm17",
        "zmm17"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm18,
        test_zmm18_is_out_of_reach_without_the_capture,
        "zmm18",
        "zmm18"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm19,
        test_zmm19_is_out_of_reach_without_the_capture,
        "zmm19",
        "zmm19"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm20,
        test_zmm20_is_out_of_reach_without_the_capture,
        "zmm20",
        "zmm20"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm21,
        test_zmm21_is_out_of_reach_without_the_capture,
        "zmm21",
        "zmm21"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm22,
        test_zmm22_is_out_of_reach_without_the_capture,
        "zmm22",
        "zmm22"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm23,
        test_zmm23_is_out_of_reach_without_the_capture,
        "zmm23",
        "zmm23"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm24,
        test_zmm24_is_out_of_reach_without_the_capture,
        "zmm24",
        "zmm24"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm25,
        test_zmm25_is_out_of_reach_without_the_capture,
        "zmm25",
        "zmm25"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm26,
        test_zmm26_is_out_of_reach_without_the_capture,
        "zmm26",
        "zmm26"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm27,
        test_zmm27_is_out_of_reach_without_the_capture,
        "zmm27",
        "zmm27"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm28,
        test_zmm28_is_out_of_reach_without_the_capture,
        "zmm28",
        "zmm28"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm29,
        test_zmm29_is_out_of_reach_without_the_capture,
        "zmm29",
        "zmm29"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm30,
        test_zmm30_is_out_of_reach_without_the_capture,
        "zmm30",
        "zmm30"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_zmm31,
        test_zmm31_is_out_of_reach_without_the_capture,
        "zmm31",
        "zmm31"
    );
}

#[cfg(target_arch = "aarch64")]
mod every_wide_register {
    use super::*;

    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z0,
        test_z0_is_out_of_reach_without_the_capture,
        "z0",
        "v0"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z1,
        test_z1_is_out_of_reach_without_the_capture,
        "z1",
        "v1"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z2,
        test_z2_is_out_of_reach_without_the_capture,
        "z2",
        "v2"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z3,
        test_z3_is_out_of_reach_without_the_capture,
        "z3",
        "v3"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z4,
        test_z4_is_out_of_reach_without_the_capture,
        "z4",
        "v4"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z5,
        test_z5_is_out_of_reach_without_the_capture,
        "z5",
        "v5"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z6,
        test_z6_is_out_of_reach_without_the_capture,
        "z6",
        "v6"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z7,
        test_z7_is_out_of_reach_without_the_capture,
        "z7",
        "v7"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z8,
        test_z8_is_out_of_reach_without_the_capture,
        "z8",
        "v8"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z9,
        test_z9_is_out_of_reach_without_the_capture,
        "z9",
        "v9"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z10,
        test_z10_is_out_of_reach_without_the_capture,
        "z10",
        "v10"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z11,
        test_z11_is_out_of_reach_without_the_capture,
        "z11",
        "v11"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z12,
        test_z12_is_out_of_reach_without_the_capture,
        "z12",
        "v12"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z13,
        test_z13_is_out_of_reach_without_the_capture,
        "z13",
        "v13"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z14,
        test_z14_is_out_of_reach_without_the_capture,
        "z14",
        "v14"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z15,
        test_z15_is_out_of_reach_without_the_capture,
        "z15",
        "v15"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z16,
        test_z16_is_out_of_reach_without_the_capture,
        "z16",
        "v16"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z17,
        test_z17_is_out_of_reach_without_the_capture,
        "z17",
        "v17"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z18,
        test_z18_is_out_of_reach_without_the_capture,
        "z18",
        "v18"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z19,
        test_z19_is_out_of_reach_without_the_capture,
        "z19",
        "v19"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z20,
        test_z20_is_out_of_reach_without_the_capture,
        "z20",
        "v20"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z21,
        test_z21_is_out_of_reach_without_the_capture,
        "z21",
        "v21"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z22,
        test_z22_is_out_of_reach_without_the_capture,
        "z22",
        "v22"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z23,
        test_z23_is_out_of_reach_without_the_capture,
        "z23",
        "v23"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z24,
        test_z24_is_out_of_reach_without_the_capture,
        "z24",
        "v24"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z25,
        test_z25_is_out_of_reach_without_the_capture,
        "z25",
        "v25"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z26,
        test_z26_is_out_of_reach_without_the_capture,
        "z26",
        "v26"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z27,
        test_z27_is_out_of_reach_without_the_capture,
        "z27",
        "v27"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z28,
        test_z28_is_out_of_reach_without_the_capture,
        "z28",
        "v28"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z29,
        test_z29_is_out_of_reach_without_the_capture,
        "z29",
        "v29"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z30,
        test_z30_is_out_of_reach_without_the_capture,
        "z30",
        "v30"
    );
    test_a_wide_register_is_reached!(
        test_the_capture_finds_a_secret_in_z31,
        test_z31_is_out_of_reach_without_the_capture,
        "z31",
        "v31"
    );
}

// ============================================================================
// The stack
// ============================================================================

/// The capture finds a secret in a frame that has already been left.
///
/// Everything below is an absence, and an absence is worth exactly this: the
/// photograph would have spoken had there been something in that frame.
#[test]
fn test_the_capture_finds_a_frame_that_was_left_full() -> Result<(), AnyError> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    forensics!({
        a_frame_left_full();
        freeze!();
    });

    let report = watch.snapshot()?;

    println!();
    report.summary("a frame left full");
    println!();

    assert!(
        report.found,
        "the capture does not reach a frame that was left, so every absence in \
         this file is the instrument standing where the evidence is: {report}"
    );

    Ok(())
}

/// A frame emptied before it is left holds nothing.
///
/// The pair with the one above: the same call site and the same shape, and the
/// only difference is whether the operation wiped.
#[test]
fn test_a_frame_emptied_before_it_is_left_holds_nothing() -> Result<(), AnyError> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    forensics!({
        a_frame_emptied();
        freeze!();
    });

    let report = watch.snapshot()?;

    println!();
    report.summary("a frame emptied");
    println!();

    // Assert zeroization!
    assert!(!report.found, "the wipe left the secret behind: {report}");

    Ok(())
}

/// Two photographs and the difference between them say the secret surfaced.
///
/// Every file above this crate reads its answer this way rather than from one
/// report: a score on its own is a number about a process that was already
/// running, and what is being asked is what one operation added to it. So the
/// difference has to be able to speak, and this is what says it can.
#[test]
fn test_the_difference_says_the_secret_surfaced() -> Result<(), AnyError> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing run yet");

    forensics!({
        a_frame_left_full();
        freeze!();
    });

    let report_after = watch.snapshot()?;

    report_after.summary_against(&report_before, "a frame left full");
    println!();

    assert!(
        report_after.found,
        "the whole secret did not surface: {report_after}"
    );

    let delta = report_after.against(&report_before);

    assert!(
        !delta.is_noise(),
        "the difference calls a whole secret surfacing noise, so every file \
         that reads a measurement this way is reading nothing: {delta}"
    );

    Ok(())
}

/// The same pair, when the operation emptied what it used.
///
/// The other half: a difference that were never noise would call every clean
/// measurement dirty, and one that is always noise would call every dirty one
/// clean. This is the side that says it can be quiet.
#[test]
fn test_the_difference_is_quiet_when_the_frame_was_emptied() -> Result<(), AnyError> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    let report_before = watch.snapshot()?;

    println!();
    report_before.summary("nothing run yet");

    forensics!({
        a_frame_emptied();
        freeze!();
    });

    let report_after = watch.snapshot()?;

    report_after.summary_against(&report_before, "a frame emptied");
    println!();

    // Assert zeroization!
    assert!(
        !report_after.found,
        "the wipe left the secret behind: {report_after}"
    );

    let delta = report_after.against(&report_before);

    assert!(
        delta.is_noise(),
        "an emptied frame moved the score: {delta}"
    );

    Ok(())
}

/// A cleanup run before the capture erases the evidence.
///
/// The trap, pinned, and the reason the one remaining rule is a rule. The
/// operation left the secret in its frame — the control above says the
/// instrument would find it — and one `drop` before the capture is enough for
/// the photograph to report a clean process.
#[test]
fn test_a_cleanup_run_before_the_capture_erases_the_evidence() -> Result<(), AnyError> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&SECRET))?;
    let waste = vec![0_u8; WASTE];

    forensics!({
        a_frame_left_full();

        drop(core::hint::black_box(waste));

        freeze!();
    });

    let report = watch.snapshot()?;

    println!();
    report.summary("a cleanup before the capture");
    println!();

    assert!(
        !report.found,
        "a call after the operation no longer erases what it left, so the \
         hazard this file is about has changed shape and every measurement \
         written against it has to be read again: {report}"
    );

    Ok(())
}

/// The same cleanup, run after the capture, leaves the evidence.
///
/// This is what the instrument is for. The cleanup writes over the frames the
/// operation left, exactly as it does above — and the answer no longer depends
/// on that, because the window was copied out of the stack before it ran.
#[test]
fn test_a_cleanup_run_after_the_capture_leaves_the_evidence() -> Result<(), AnyError> {
    alone!();

    let mut watch = Forensics::watching(&backwards(&SECRET))?;
    let waste = vec![0_u8; WASTE];

    forensics!({
        a_frame_left_full();
        freeze!();

        drop(core::hint::black_box(waste));
    });

    let report = watch.snapshot()?;

    println!();
    report.summary("a cleanup after the capture");
    println!();

    assert!(
        report.found,
        "the cleanup erased the evidence even though the capture had already \
         taken it off the stack: {report}"
    );

    Ok(())
}

// ============================================================================
// A watch built after the capture
// ============================================================================

/// A value that does not exist until the operation produces it has no needle
/// beforehand, so its watch is built after the capture. The capture has already
/// written the registers and the window into memory by then, and building the
/// watch writes over neither.
#[test]
fn test_a_wide_register_is_found_by_a_watch_built_after_the_capture() -> Result<(), AnyError> {
    alone!();

    wide!();

    pick_spiller();

    forensics!({
        a_wide_register!();

        freeze!();
    });

    let mut watch = Forensics::watching(&backwards(&HELD))?;

    let report = watch.snapshot()?;

    assert!(
        report.found,
        "the secret the capture took was lost to the watch built after it: {report}",
    );

    Ok(())
}

/// A capture that runs before any form is picked runs the narrowest one, which
/// does not reach a wide register; a watch built afterwards picks too late.
#[test]
fn test_a_wide_register_is_out_of_reach_when_the_form_is_picked_after_the_capture()
-> Result<(), AnyError> {
    alone!();

    wide!();

    forensics!({
        a_wide_register!();

        freeze!();
    });

    let mut watch = Forensics::watching(&backwards(&HELD))?;

    let report = watch.snapshot()?;

    assert!(
        !report.found,
        "a capture that ran before any form was picked reached the widest \
         registers, so the pick before it proves nothing: {report}",
    );

    Ok(())
}

#[test]
fn test_a_frame_left_full_is_found_by_a_watch_built_after_the_capture() -> Result<(), AnyError> {
    alone!();

    forensics!({
        a_frame_left_full();
        freeze!();
    });

    let mut watch = Forensics::watching(&backwards(&SECRET))?;

    let report = watch.snapshot()?;

    assert!(
        report.found,
        "the frame the capture took was lost to the watch built after it: {report}",
    );

    Ok(())
}
