// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! One photograph with a needle for every register, for a frame and for the
//! heap: every one planted and each found in its own report, none planted, or
//! every one planted and emptied, and none found.
//!
//! # A process each
//!
//! The memory swept is the whole process's, so a test sharing it is another
//! place a needle could be. `nextest`, not `cargo test`.

#![cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::analysis::state::NEEDLES;
use crate::{AnyError, Forensics, QUIET, Report};

/// As wide as the widest vector register a form fills: a `zmm`.
#[cfg(target_arch = "x86_64")]
const ROW: usize = 64;

/// As wide as the widest vector register a form fills: a `z` at the longest
/// vector length SVE allows.
#[cfg(target_arch = "aarch64")]
const ROW: usize = 256;

/// How much of a row a needle in memory is.
const IN_MEMORY: usize = 32;

/// How much of a row a general register holds.
const GENERAL: usize = 8;

/// Row `k`, whose bytes differ from every other row's at every offset.
const fn needle(k: usize) -> [u8; ROW] {
    let mask = ((k + 1) as u8).wrapping_mul(0x3B);
    let mut needle = [0_u8; ROW];
    let mut at = 0;

    while at < ROW {
        needle[at] = (at as u8).wrapping_mul(37).wrapping_add(11) ^ mask;
        at += 1;
    }

    needle
}

/// Every row, read by the planting's assembly straight from a mapping the sweep
/// does not read.
static ROWS: [[u8; ROW]; NEEDLES] = {
    let mut all = [[0_u8; ROW]; NEEDLES];
    let mut k = 0;

    while k < NEEDLES {
        all[k] = needle(k);
        k += 1;
    }

    all
};

/// Whether the planting leaves what it loaded, read by its assembly.
static PLANTED: AtomicUsize = AtomicUsize::new(0);

/// Whether the planting empties what it loaded before the capture, read by
/// its assembly.
static EMPTIED: AtomicUsize = AtomicUsize::new(0);

macro_rules! alone {
    () => {
        if std::env::var_os("NEXTEST").is_none() {
            eprintln!("skipped: this test needs a process of its own. `cargo nextest run`.");

            return Ok(());
        }
    };
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seeded {
    Planted,
    Never,
    Emptied,
}

fn backwards(of: &[u8]) -> Vec<u8> {
    of.iter().rev().copied().collect()
}

/// Byte by byte and volatile, so that no copy passes through a register the
/// compiler picks.
fn giving(into: &mut [u8], from: &[u8]) {
    for (at, byte) in from.iter().enumerate() {
        // SAFETY: `at` indexes a destination at least as wide as the source,
        // which is every caller here.
        unsafe { into.as_mut_ptr().add(at).write_volatile(*byte) };
    }
}

/// Byte by byte and volatile, so that the compiler cannot drop a wipe nothing
/// reads afterwards.
fn taking(from: &mut [u8]) {
    for at in 0..from.len() {
        // SAFETY: `at` indexes inside `from`.
        unsafe { from.as_mut_ptr().add(at).write_volatile(0) };
    }
}

/// One watch over every row given, each cut to its width, and the photograph
/// from before.
fn watching(rows: &[(usize, usize)]) -> Result<(Forensics, Vec<Report>), AnyError> {
    let reversed: Vec<Vec<u8>> = rows
        .iter()
        .map(|(k, wide)| backwards(&ROWS[*k][..*wide]))
        .collect();
    let needles: Vec<&[u8]> = reversed.iter().map(Vec::as_slice).collect();

    let mut watch = Forensics::watching_each(&needles)?;
    let befores = watch.snapshot_each()?;

    Ok((watch, befores))
}

/// The photograph after, held to what was seeded, needle by needle.
fn answered(watch: &mut Forensics, befores: &[Report], seeded: Seeded) -> Result<(), AnyError> {
    let reports = watch.snapshot_each()?;
    let n = reports.len();

    assert_eq!(n, befores.len(), "one report per needle");

    for (k, report) in reports.iter().enumerate() {
        if seeded == Seeded::Planted {
            assert!(
                report.found,
                "needle {} of {n}, planted, found nothing: {report}",
                k + 1,
            );
        } else {
            assert!(
                !report.found,
                "needle {} of {n}, with nothing left to find, found its secret: {report}",
                k + 1,
            );

            assert!(
                report.widest <= QUIET,
                "needle {} of {n}, with nothing left to find, read a run of {}: {report}",
                k + 1,
                report.widest,
            );

            let delta = report.against(&befores[k]);

            assert!(
                delta.is_noise(),
                "needle {} of {n}, with nothing left to find, moved the score: {delta}",
                k + 1,
            );
        }
    }

    Ok(())
}

// ============================================================================
// A frame, and the heap
// ============================================================================

/// A frame of its own holding every row, left behind when it returns.
#[inline(never)]
fn a_frame(seeded: Seeded) {
    let mut held = [[0_u8; IN_MEMORY]; NEEDLES];

    if seeded != Seeded::Never {
        for (slot, row) in held.iter_mut().zip(&ROWS) {
            giving(slot, &row[..IN_MEMORY]);
        }
    }

    core::hint::black_box(&held);

    if seeded == Seeded::Emptied {
        for slot in &mut held {
            taking(slot);
        }
    }

    core::hint::black_box(&held);
}

/// Every row, as wide as a needle in memory.
fn in_memory() -> Vec<(usize, usize)> {
    (0..NEEDLES).map(|k| (k, IN_MEMORY)).collect()
}

pub(crate) fn in_a_frame(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    let (mut watch, befores) = watching(&in_memory())?;

    crate::forensics!({
        crate::capture(|| {
            a_frame(seeded);
        });
    });

    answered(&mut watch, &befores, seeded)
}

pub(crate) fn in_the_heap(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    let (mut watch, befores) = watching(&in_memory())?;

    if seeded != Seeded::Never {
        for row in &ROWS {
            let held = Box::leak(Box::new([0_u8; IN_MEMORY]));

            giving(held, &row[..IN_MEMORY]);

            if seeded == Seeded::Emptied {
                taking(held);
            }
        }
    }

    answered(&mut watch, &befores, seeded)
}

/// The tests of one runner, in a module named after it.
macro_rules! three {
    ($runner:ident) => {
        mod $runner {
            use crate::AnyError;
            use crate::tests::watches::Seeded;

            #[test]
            fn test_every_one_planted_is_found_by_its_own_needle() -> Result<(), AnyError> {
                super::$runner(Seeded::Planted)
            }

            #[test]
            fn test_none_planted_leaves_every_needle_clean() -> Result<(), AnyError> {
                super::$runner(Seeded::Never)
            }

            #[test]
            fn test_every_one_planted_and_emptied_leaves_every_needle_clean()
            -> Result<(), AnyError> {
                super::$runner(Seeded::Emptied)
            }
        }
    };
}

three!(in_a_frame);
three!(in_the_heap);

// ============================================================================
// Every register, on x86_64
// ============================================================================

/// One block that loads every register listed from its row, empties them all
/// unless [`PLANTED`], and empties them all again if [`EMPTIED`].
#[cfg(target_arch = "x86_64")]
macro_rules! plant_x86 {
    (
        before: [$($before:literal),* $(,)?],
        after: [$($after:literal),* $(,)?],
        generals: [$(($g:literal, $gz:literal, $go:literal)),* $(,)?],
        vectors: [$(($load:literal, $v:literal, $vz:literal, $vo:literal)),* $(,)?],
        operands: [$($operands:tt)*]
    ) => {
        core::arch::asm!(
            $($before,)*
            $(
                concat!("mov ", $g, ", qword ptr [rip + {rows} + ", $go, "]"),
            )*
            $(
                concat!($load, " ", $v, ", [rip + {rows} + ", $vo, "]"),
            )*
            "cmp qword ptr [rip + {planted}], 0",
            "jne 2f",
            $(concat!("xor ", $gz, ", ", $gz),)*
            $($vz,)*
            "2:",
            "cmp qword ptr [rip + {emptied}], 0",
            "je 3f",
            $(concat!("xor ", $gz, ", ", $gz),)*
            $($vz,)*
            "3:",
            $($after,)*
            rows = sym ROWS,
            planted = sym PLANTED,
            emptied = sym EMPTIED,
            $($operands)*
        )
    };
}

/// The generals from the first rows, and the vectors from the rows after them.
#[cfg(target_arch = "x86_64")]
fn widths(generals: usize, vectors: usize, wide: usize) -> Vec<(usize, usize)> {
    (0..generals)
        .map(|k| (k, GENERAL))
        .chain((generals..generals + vectors).map(|k| (k, wide)))
        .collect()
}

/// What the planting's assembly reads to decide.
fn setting(seeded: Seeded) {
    PLANTED.store(usize::from(seeded != Seeded::Never), Ordering::Relaxed);
    EMPTIED.store(usize::from(seeded == Seeded::Emptied), Ordering::Relaxed);
}

/// Every general register but `rsp`.
#[cfg(target_arch = "x86_64")]
const SPILL_GENERALS: usize = 15;

/// Every general register an assembly block may name: all but `rbx`, `rbp`
/// and `rsp`.
#[cfg(target_arch = "x86_64")]
const INLINED_GENERALS: usize = 13;

// ----------------------------------------------------------------------------
// Through the spill routine, which reaches `rbx` and `rbp`
// ----------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub(crate) fn spill_sse(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    let (mut watch, befores) = watching(&widths(SPILL_GENERALS, 16, 16))?;

    setting(seeded);

    // SAFETY: `rbx` and `rbp` are pushed before they are written and popped
    // after the call, so nothing outside sees them changed; every other
    // register written is declared; every load reads a row of a static.
    unsafe {
        plant_x86!(
            before: ["push rbx", "push rbp"],
            after: ["call {spill}", "pop rbp", "pop rbx"],
            generals: [
                ("rax", "eax", "0"),
                ("rbx", "ebx", "64"),
                ("rcx", "ecx", "128"),
                ("rdx", "edx", "192"),
                ("rsi", "esi", "256"),
                ("rdi", "edi", "320"),
                ("rbp", "ebp", "384"),
                ("r8", "r8d", "448"),
                ("r9", "r9d", "512"),
                ("r10", "r10d", "576"),
                ("r11", "r11d", "640"),
                ("r12", "r12d", "704"),
                ("r13", "r13d", "768"),
                ("r14", "r14d", "832"),
                ("r15", "r15d", "896"),
            ],
            vectors: [
                ("movdqu", "xmm0", "pxor xmm0, xmm0", "960"),
                ("movdqu", "xmm1", "pxor xmm1, xmm1", "1024"),
                ("movdqu", "xmm2", "pxor xmm2, xmm2", "1088"),
                ("movdqu", "xmm3", "pxor xmm3, xmm3", "1152"),
                ("movdqu", "xmm4", "pxor xmm4, xmm4", "1216"),
                ("movdqu", "xmm5", "pxor xmm5, xmm5", "1280"),
                ("movdqu", "xmm6", "pxor xmm6, xmm6", "1344"),
                ("movdqu", "xmm7", "pxor xmm7, xmm7", "1408"),
                ("movdqu", "xmm8", "pxor xmm8, xmm8", "1472"),
                ("movdqu", "xmm9", "pxor xmm9, xmm9", "1536"),
                ("movdqu", "xmm10", "pxor xmm10, xmm10", "1600"),
                ("movdqu", "xmm11", "pxor xmm11, xmm11", "1664"),
                ("movdqu", "xmm12", "pxor xmm12, xmm12", "1728"),
                ("movdqu", "xmm13", "pxor xmm13, xmm13", "1792"),
                ("movdqu", "xmm14", "pxor xmm14, xmm14", "1856"),
                ("movdqu", "xmm15", "pxor xmm15, xmm15", "1920"),
            ],
            operands: [
                spill = sym crate::spiller::redoubt_spill_sse,
                out("rax") _, out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
                out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                out("r12") _, out("r13") _, out("r14") _, out("r15") _,
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            ]
        );
    }

    answered(&mut watch, &befores, seeded)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn spill_avx(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    if !std::arch::is_x86_feature_detected!("avx") {
        eprintln!("skipped: no AVX here, so there is no such register to fill.");

        return Ok(());
    }

    // SAFETY: the feature it is compiled for was just detected.
    unsafe { spill_avx_on(seeded) }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn spill_avx_on(seeded: Seeded) -> Result<(), AnyError> {
    let (mut watch, befores) = watching(&widths(SPILL_GENERALS, 16, 32))?;

    setting(seeded);

    // SAFETY: as in `spill_sse`.
    unsafe {
        plant_x86!(
            before: ["push rbx", "push rbp"],
            after: ["call {spill}", "pop rbp", "pop rbx"],
            generals: [
                ("rax", "eax", "0"),
                ("rbx", "ebx", "64"),
                ("rcx", "ecx", "128"),
                ("rdx", "edx", "192"),
                ("rsi", "esi", "256"),
                ("rdi", "edi", "320"),
                ("rbp", "ebp", "384"),
                ("r8", "r8d", "448"),
                ("r9", "r9d", "512"),
                ("r10", "r10d", "576"),
                ("r11", "r11d", "640"),
                ("r12", "r12d", "704"),
                ("r13", "r13d", "768"),
                ("r14", "r14d", "832"),
                ("r15", "r15d", "896"),
            ],
            vectors: [
                ("vmovdqu", "ymm0", "vxorps ymm0, ymm0, ymm0", "960"),
                ("vmovdqu", "ymm1", "vxorps ymm1, ymm1, ymm1", "1024"),
                ("vmovdqu", "ymm2", "vxorps ymm2, ymm2, ymm2", "1088"),
                ("vmovdqu", "ymm3", "vxorps ymm3, ymm3, ymm3", "1152"),
                ("vmovdqu", "ymm4", "vxorps ymm4, ymm4, ymm4", "1216"),
                ("vmovdqu", "ymm5", "vxorps ymm5, ymm5, ymm5", "1280"),
                ("vmovdqu", "ymm6", "vxorps ymm6, ymm6, ymm6", "1344"),
                ("vmovdqu", "ymm7", "vxorps ymm7, ymm7, ymm7", "1408"),
                ("vmovdqu", "ymm8", "vxorps ymm8, ymm8, ymm8", "1472"),
                ("vmovdqu", "ymm9", "vxorps ymm9, ymm9, ymm9", "1536"),
                ("vmovdqu", "ymm10", "vxorps ymm10, ymm10, ymm10", "1600"),
                ("vmovdqu", "ymm11", "vxorps ymm11, ymm11, ymm11", "1664"),
                ("vmovdqu", "ymm12", "vxorps ymm12, ymm12, ymm12", "1728"),
                ("vmovdqu", "ymm13", "vxorps ymm13, ymm13, ymm13", "1792"),
                ("vmovdqu", "ymm14", "vxorps ymm14, ymm14, ymm14", "1856"),
                ("vmovdqu", "ymm15", "vxorps ymm15, ymm15, ymm15", "1920"),
            ],
            operands: [
                spill = sym crate::spiller::redoubt_spill_avx,
                out("rax") _, out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
                out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                out("r12") _, out("r13") _, out("r14") _, out("r15") _,
                out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
                out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
                out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
                out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
            ]
        );
    }

    answered(&mut watch, &befores, seeded)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn spill_avx512(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    if !std::arch::is_x86_feature_detected!("avx512f") {
        eprintln!("skipped: no AVX-512 here, so there is no such register to fill.");

        return Ok(());
    }

    // SAFETY: the feature it is compiled for was just detected.
    unsafe { spill_avx512_on(seeded) }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn spill_avx512_on(seeded: Seeded) -> Result<(), AnyError> {
    let (mut watch, befores) = watching(&widths(SPILL_GENERALS, 32, 64))?;

    setting(seeded);

    // SAFETY: as in `spill_sse`.
    unsafe {
        plant_x86!(
            before: ["push rbx", "push rbp"],
            after: ["call {spill}", "pop rbp", "pop rbx"],
            generals: [
                ("rax", "eax", "0"),
                ("rbx", "ebx", "64"),
                ("rcx", "ecx", "128"),
                ("rdx", "edx", "192"),
                ("rsi", "esi", "256"),
                ("rdi", "edi", "320"),
                ("rbp", "ebp", "384"),
                ("r8", "r8d", "448"),
                ("r9", "r9d", "512"),
                ("r10", "r10d", "576"),
                ("r11", "r11d", "640"),
                ("r12", "r12d", "704"),
                ("r13", "r13d", "768"),
                ("r14", "r14d", "832"),
                ("r15", "r15d", "896"),
            ],
            vectors: [
                ("vmovdqu64", "zmm0", "vpxord zmm0, zmm0, zmm0", "960"),
                ("vmovdqu64", "zmm1", "vpxord zmm1, zmm1, zmm1", "1024"),
                ("vmovdqu64", "zmm2", "vpxord zmm2, zmm2, zmm2", "1088"),
                ("vmovdqu64", "zmm3", "vpxord zmm3, zmm3, zmm3", "1152"),
                ("vmovdqu64", "zmm4", "vpxord zmm4, zmm4, zmm4", "1216"),
                ("vmovdqu64", "zmm5", "vpxord zmm5, zmm5, zmm5", "1280"),
                ("vmovdqu64", "zmm6", "vpxord zmm6, zmm6, zmm6", "1344"),
                ("vmovdqu64", "zmm7", "vpxord zmm7, zmm7, zmm7", "1408"),
                ("vmovdqu64", "zmm8", "vpxord zmm8, zmm8, zmm8", "1472"),
                ("vmovdqu64", "zmm9", "vpxord zmm9, zmm9, zmm9", "1536"),
                ("vmovdqu64", "zmm10", "vpxord zmm10, zmm10, zmm10", "1600"),
                ("vmovdqu64", "zmm11", "vpxord zmm11, zmm11, zmm11", "1664"),
                ("vmovdqu64", "zmm12", "vpxord zmm12, zmm12, zmm12", "1728"),
                ("vmovdqu64", "zmm13", "vpxord zmm13, zmm13, zmm13", "1792"),
                ("vmovdqu64", "zmm14", "vpxord zmm14, zmm14, zmm14", "1856"),
                ("vmovdqu64", "zmm15", "vpxord zmm15, zmm15, zmm15", "1920"),
                ("vmovdqu64", "zmm16", "vpxord zmm16, zmm16, zmm16", "1984"),
                ("vmovdqu64", "zmm17", "vpxord zmm17, zmm17, zmm17", "2048"),
                ("vmovdqu64", "zmm18", "vpxord zmm18, zmm18, zmm18", "2112"),
                ("vmovdqu64", "zmm19", "vpxord zmm19, zmm19, zmm19", "2176"),
                ("vmovdqu64", "zmm20", "vpxord zmm20, zmm20, zmm20", "2240"),
                ("vmovdqu64", "zmm21", "vpxord zmm21, zmm21, zmm21", "2304"),
                ("vmovdqu64", "zmm22", "vpxord zmm22, zmm22, zmm22", "2368"),
                ("vmovdqu64", "zmm23", "vpxord zmm23, zmm23, zmm23", "2432"),
                ("vmovdqu64", "zmm24", "vpxord zmm24, zmm24, zmm24", "2496"),
                ("vmovdqu64", "zmm25", "vpxord zmm25, zmm25, zmm25", "2560"),
                ("vmovdqu64", "zmm26", "vpxord zmm26, zmm26, zmm26", "2624"),
                ("vmovdqu64", "zmm27", "vpxord zmm27, zmm27, zmm27", "2688"),
                ("vmovdqu64", "zmm28", "vpxord zmm28, zmm28, zmm28", "2752"),
                ("vmovdqu64", "zmm29", "vpxord zmm29, zmm29, zmm29", "2816"),
                ("vmovdqu64", "zmm30", "vpxord zmm30, zmm30, zmm30", "2880"),
                ("vmovdqu64", "zmm31", "vpxord zmm31, zmm31, zmm31", "2944"),
            ],
            operands: [
                spill = sym crate::spiller::redoubt_spill_avx512,
                out("rax") _, out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
                out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                out("r12") _, out("r13") _, out("r14") _, out("r15") _,
                out("zmm0") _, out("zmm1") _, out("zmm2") _, out("zmm3") _,
                out("zmm4") _, out("zmm5") _, out("zmm6") _, out("zmm7") _,
                out("zmm8") _, out("zmm9") _, out("zmm10") _, out("zmm11") _,
                out("zmm12") _, out("zmm13") _, out("zmm14") _, out("zmm15") _,
                out("zmm16") _, out("zmm17") _, out("zmm18") _, out("zmm19") _,
                out("zmm20") _, out("zmm21") _, out("zmm22") _, out("zmm23") _,
                out("zmm24") _, out("zmm25") _, out("zmm26") _, out("zmm27") _,
                out("zmm28") _, out("zmm29") _, out("zmm30") _, out("zmm31") _,
            ]
        );
    }

    answered(&mut watch, &befores, seeded)
}

// ----------------------------------------------------------------------------
// Through `capture`, with the planting as the operation
// ----------------------------------------------------------------------------

/// `rbx` and `rbp`, which an assembly block may not name, planted from their
/// rows and kept so across a call to `$then`, which runs the capture.
#[cfg(target_arch = "x86_64")]
macro_rules! around_callee_saved_x86 {
    ($rbx:literal, $rbp:literal, $then:ident) => {
        // SAFETY: `rbx`, `rbp` and `r12` are given back as they were found
        // before the block ends, and the stack pointer from `r12`; the call is
        // made on a stack aligned to sixteen, and everything the called
        // function may change is declared by the ABI clobber; every load reads
        // a row of a static.
        unsafe {
            plant_x86!(
                before: ["push rbx", "push rbp", "push r12", "mov r12, rsp", "and rsp, -16"],
                after: ["call {then}", "mov rsp, r12", "pop r12", "pop rbp", "pop rbx"],
                generals: [
                    ("rbx", "ebx", $rbx),
                    ("rbp", "ebp", $rbp),
                ],
                vectors: [],
                operands: [
                    then = sym $then,
                    clobber_abi("C"),
                ]
            );
        }
    };
}

/// The rows the callee-saved registers are planted from, appended: `from`
/// is the first row nothing else takes, past the vectors on `x86_64` and
/// between the generals and [`VECTORS`] on `aarch64`.
fn with_callee_saved(mut rows: Vec<(usize, usize)>, from: usize) -> Vec<(usize, usize)> {
    rows.push((from, GENERAL));
    rows.push((from + 1, GENERAL));

    rows
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn capture_sse(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    let (mut watch, befores) = watching(&with_callee_saved(widths(INLINED_GENERALS, 16, 16), 29))?;

    crate::spiller::use_spiller(crate::spiller::Form::Sse);

    setting(seeded);

    extern "C" fn capture_here() {
        crate::capture(|| {
            plant_sse();
        });
    }

    crate::forensics!({
        around_callee_saved_x86!("1856", "1920", capture_here);
    });

    answered(&mut watch, &befores, seeded)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn plant_sse() {
    // SAFETY: every register written is declared, and every load reads a row
    // of a static.
    unsafe {
        plant_x86!(
            before: [],
            after: [],
            generals: [
                ("rax", "eax", "0"),
                ("rcx", "ecx", "64"),
                ("rdx", "edx", "128"),
                ("rsi", "esi", "192"),
                ("rdi", "edi", "256"),
                ("r8", "r8d", "320"),
                ("r9", "r9d", "384"),
                ("r10", "r10d", "448"),
                ("r11", "r11d", "512"),
                ("r12", "r12d", "576"),
                ("r13", "r13d", "640"),
                ("r14", "r14d", "704"),
                ("r15", "r15d", "768"),
            ],
            vectors: [
                ("movdqu", "xmm0", "pxor xmm0, xmm0", "832"),
                ("movdqu", "xmm1", "pxor xmm1, xmm1", "896"),
                ("movdqu", "xmm2", "pxor xmm2, xmm2", "960"),
                ("movdqu", "xmm3", "pxor xmm3, xmm3", "1024"),
                ("movdqu", "xmm4", "pxor xmm4, xmm4", "1088"),
                ("movdqu", "xmm5", "pxor xmm5, xmm5", "1152"),
                ("movdqu", "xmm6", "pxor xmm6, xmm6", "1216"),
                ("movdqu", "xmm7", "pxor xmm7, xmm7", "1280"),
                ("movdqu", "xmm8", "pxor xmm8, xmm8", "1344"),
                ("movdqu", "xmm9", "pxor xmm9, xmm9", "1408"),
                ("movdqu", "xmm10", "pxor xmm10, xmm10", "1472"),
                ("movdqu", "xmm11", "pxor xmm11, xmm11", "1536"),
                ("movdqu", "xmm12", "pxor xmm12, xmm12", "1600"),
                ("movdqu", "xmm13", "pxor xmm13, xmm13", "1664"),
                ("movdqu", "xmm14", "pxor xmm14, xmm14", "1728"),
                ("movdqu", "xmm15", "pxor xmm15, xmm15", "1792"),
            ],
            operands: [
                out("rax") _, out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
                out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                out("r12") _, out("r13") _, out("r14") _, out("r15") _,
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            ]
        );
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn capture_avx(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    if !std::arch::is_x86_feature_detected!("avx") {
        eprintln!("skipped: no AVX here, so there is no such register to fill.");

        return Ok(());
    }

    let (mut watch, befores) = watching(&with_callee_saved(widths(INLINED_GENERALS, 16, 32), 29))?;

    crate::spiller::use_spiller(crate::spiller::Form::Avx);

    setting(seeded);

    extern "C" fn capture_here() {
        crate::capture(|| {
            plant_avx();
        });
    }

    crate::forensics!({
        around_callee_saved_x86!("1856", "1920", capture_here);
    });

    answered(&mut watch, &befores, seeded)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn plant_avx() {
    // SAFETY: as in `plant_sse`, and it is reached only once AVX was detected.
    unsafe {
        plant_x86!(
            before: [],
            after: [],
            generals: [
                ("rax", "eax", "0"),
                ("rcx", "ecx", "64"),
                ("rdx", "edx", "128"),
                ("rsi", "esi", "192"),
                ("rdi", "edi", "256"),
                ("r8", "r8d", "320"),
                ("r9", "r9d", "384"),
                ("r10", "r10d", "448"),
                ("r11", "r11d", "512"),
                ("r12", "r12d", "576"),
                ("r13", "r13d", "640"),
                ("r14", "r14d", "704"),
                ("r15", "r15d", "768"),
            ],
            vectors: [
                ("vmovdqu", "ymm0", "vxorps ymm0, ymm0, ymm0", "832"),
                ("vmovdqu", "ymm1", "vxorps ymm1, ymm1, ymm1", "896"),
                ("vmovdqu", "ymm2", "vxorps ymm2, ymm2, ymm2", "960"),
                ("vmovdqu", "ymm3", "vxorps ymm3, ymm3, ymm3", "1024"),
                ("vmovdqu", "ymm4", "vxorps ymm4, ymm4, ymm4", "1088"),
                ("vmovdqu", "ymm5", "vxorps ymm5, ymm5, ymm5", "1152"),
                ("vmovdqu", "ymm6", "vxorps ymm6, ymm6, ymm6", "1216"),
                ("vmovdqu", "ymm7", "vxorps ymm7, ymm7, ymm7", "1280"),
                ("vmovdqu", "ymm8", "vxorps ymm8, ymm8, ymm8", "1344"),
                ("vmovdqu", "ymm9", "vxorps ymm9, ymm9, ymm9", "1408"),
                ("vmovdqu", "ymm10", "vxorps ymm10, ymm10, ymm10", "1472"),
                ("vmovdqu", "ymm11", "vxorps ymm11, ymm11, ymm11", "1536"),
                ("vmovdqu", "ymm12", "vxorps ymm12, ymm12, ymm12", "1600"),
                ("vmovdqu", "ymm13", "vxorps ymm13, ymm13, ymm13", "1664"),
                ("vmovdqu", "ymm14", "vxorps ymm14, ymm14, ymm14", "1728"),
                ("vmovdqu", "ymm15", "vxorps ymm15, ymm15, ymm15", "1792"),
            ],
            operands: [
                out("rax") _, out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
                out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                out("r12") _, out("r13") _, out("r14") _, out("r15") _,
                out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
                out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
                out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
                out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
            ]
        );
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn capture_avx512(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    if !std::arch::is_x86_feature_detected!("avx512f") {
        eprintln!("skipped: no AVX-512 here, so there is no such register to fill.");

        return Ok(());
    }

    let (mut watch, befores) = watching(&with_callee_saved(widths(INLINED_GENERALS, 32, 64), 45))?;

    crate::spiller::use_spiller(crate::spiller::Form::Avx512);

    setting(seeded);

    extern "C" fn capture_here() {
        crate::capture(|| {
            plant_avx512();
        });
    }

    crate::forensics!({
        around_callee_saved_x86!("2880", "2944", capture_here);
    });

    answered(&mut watch, &befores, seeded)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn plant_avx512() {
    // SAFETY: as in `plant_sse`, and it is reached only once AVX-512 was
    // detected.
    unsafe {
        plant_x86!(
            before: [],
            after: [],
            generals: [
                ("rax", "eax", "0"),
                ("rcx", "ecx", "64"),
                ("rdx", "edx", "128"),
                ("rsi", "esi", "192"),
                ("rdi", "edi", "256"),
                ("r8", "r8d", "320"),
                ("r9", "r9d", "384"),
                ("r10", "r10d", "448"),
                ("r11", "r11d", "512"),
                ("r12", "r12d", "576"),
                ("r13", "r13d", "640"),
                ("r14", "r14d", "704"),
                ("r15", "r15d", "768"),
            ],
            vectors: [
                ("vmovdqu64", "zmm0", "vpxord zmm0, zmm0, zmm0", "832"),
                ("vmovdqu64", "zmm1", "vpxord zmm1, zmm1, zmm1", "896"),
                ("vmovdqu64", "zmm2", "vpxord zmm2, zmm2, zmm2", "960"),
                ("vmovdqu64", "zmm3", "vpxord zmm3, zmm3, zmm3", "1024"),
                ("vmovdqu64", "zmm4", "vpxord zmm4, zmm4, zmm4", "1088"),
                ("vmovdqu64", "zmm5", "vpxord zmm5, zmm5, zmm5", "1152"),
                ("vmovdqu64", "zmm6", "vpxord zmm6, zmm6, zmm6", "1216"),
                ("vmovdqu64", "zmm7", "vpxord zmm7, zmm7, zmm7", "1280"),
                ("vmovdqu64", "zmm8", "vpxord zmm8, zmm8, zmm8", "1344"),
                ("vmovdqu64", "zmm9", "vpxord zmm9, zmm9, zmm9", "1408"),
                ("vmovdqu64", "zmm10", "vpxord zmm10, zmm10, zmm10", "1472"),
                ("vmovdqu64", "zmm11", "vpxord zmm11, zmm11, zmm11", "1536"),
                ("vmovdqu64", "zmm12", "vpxord zmm12, zmm12, zmm12", "1600"),
                ("vmovdqu64", "zmm13", "vpxord zmm13, zmm13, zmm13", "1664"),
                ("vmovdqu64", "zmm14", "vpxord zmm14, zmm14, zmm14", "1728"),
                ("vmovdqu64", "zmm15", "vpxord zmm15, zmm15, zmm15", "1792"),
                ("vmovdqu64", "zmm16", "vpxord zmm16, zmm16, zmm16", "1856"),
                ("vmovdqu64", "zmm17", "vpxord zmm17, zmm17, zmm17", "1920"),
                ("vmovdqu64", "zmm18", "vpxord zmm18, zmm18, zmm18", "1984"),
                ("vmovdqu64", "zmm19", "vpxord zmm19, zmm19, zmm19", "2048"),
                ("vmovdqu64", "zmm20", "vpxord zmm20, zmm20, zmm20", "2112"),
                ("vmovdqu64", "zmm21", "vpxord zmm21, zmm21, zmm21", "2176"),
                ("vmovdqu64", "zmm22", "vpxord zmm22, zmm22, zmm22", "2240"),
                ("vmovdqu64", "zmm23", "vpxord zmm23, zmm23, zmm23", "2304"),
                ("vmovdqu64", "zmm24", "vpxord zmm24, zmm24, zmm24", "2368"),
                ("vmovdqu64", "zmm25", "vpxord zmm25, zmm25, zmm25", "2432"),
                ("vmovdqu64", "zmm26", "vpxord zmm26, zmm26, zmm26", "2496"),
                ("vmovdqu64", "zmm27", "vpxord zmm27, zmm27, zmm27", "2560"),
                ("vmovdqu64", "zmm28", "vpxord zmm28, zmm28, zmm28", "2624"),
                ("vmovdqu64", "zmm29", "vpxord zmm29, zmm29, zmm29", "2688"),
                ("vmovdqu64", "zmm30", "vpxord zmm30, zmm30, zmm30", "2752"),
                ("vmovdqu64", "zmm31", "vpxord zmm31, zmm31, zmm31", "2816"),
            ],
            operands: [
                out("rax") _, out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
                out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                out("r12") _, out("r13") _, out("r14") _, out("r15") _,
                out("zmm0") _, out("zmm1") _, out("zmm2") _, out("zmm3") _,
                out("zmm4") _, out("zmm5") _, out("zmm6") _, out("zmm7") _,
                out("zmm8") _, out("zmm9") _, out("zmm10") _, out("zmm11") _,
                out("zmm12") _, out("zmm13") _, out("zmm14") _, out("zmm15") _,
                out("zmm16") _, out("zmm17") _, out("zmm18") _, out("zmm19") _,
                out("zmm20") _, out("zmm21") _, out("zmm22") _, out("zmm23") _,
                out("zmm24") _, out("zmm25") _, out("zmm26") _, out("zmm27") _,
                out("zmm28") _, out("zmm29") _, out("zmm30") _, out("zmm31") _,
            ]
        );
    }
}

#[cfg(target_arch = "x86_64")]
three!(spill_sse);
#[cfg(target_arch = "x86_64")]
three!(spill_avx);
#[cfg(target_arch = "x86_64")]
three!(spill_avx512);
#[cfg(target_arch = "x86_64")]
three!(capture_sse);
#[cfg(target_arch = "x86_64")]
three!(capture_avx);
#[cfg(target_arch = "x86_64")]
three!(capture_avx512);

// ============================================================================
// Every register, on aarch64
// ============================================================================

/// One block that loads every general listed and every `q` from its row,
/// empties them all unless [`PLANTED`], and empties them all again if
/// [`EMPTIED`]. `base` is the register it addresses the rows through.
#[cfg(target_arch = "aarch64")]
macro_rules! plant_neon {
    (
        base: $base:literal,
        before: [$($before:literal),* $(,)?],
        after: [$($after:literal),* $(,)?],
        generals: [$(($g:literal, $go:literal)),* $(,)?],
        operands: [$($operands:tt)*]
    ) => {
        plant_neon!(@with
            base: $base,
            before: [$($before),*],
            after: [$($after),*],
            generals: [$(($g, $go)),*],
            vectors: [
                ("0", "0"), ("1", "256"), ("2", "512"), ("3", "768"),
                ("4", "1024"), ("5", "1280"), ("6", "1536"), ("7", "1792"),
                ("8", "2048"), ("9", "2304"), ("10", "2560"), ("11", "2816"),
                ("12", "3072"), ("13", "3328"), ("14", "3584"), ("15", "3840"),
                ("16", "4096"), ("17", "4352"), ("18", "4608"), ("19", "4864"),
                ("20", "5120"), ("21", "5376"), ("22", "5632"), ("23", "5888"),
                ("24", "6144"), ("25", "6400"), ("26", "6656"), ("27", "6912"),
                ("28", "7168"), ("29", "7424"), ("30", "7680"), ("31", "7936"),
            ],
            operands: [$($operands)*]
        )
    };
    (@with
        base: $base:literal,
        before: [$($before:literal),*],
        after: [$($after:literal),*],
        generals: [$(($g:literal, $go:literal)),*],
        vectors: [$(($v:literal, $vo:literal)),* $(,)?],
        operands: [$($operands:tt)*]
    ) => {
        core::arch::asm!(
            $($before,)*
            concat!("adrp ", $base, ", {rows}"),
            concat!("add ", $base, ", ", $base, ", :lo12:{rows}"),
            $(concat!("ldr ", $g, ", [", $base, ", #", $go, "]"),)*
            concat!("add ", $base, ", ", $base, ", #8192"),
            $(concat!("ldr q", $v, ", [", $base, ", #", $vo, "]"),)*
            concat!("adrp ", $base, ", {planted}"),
            concat!("ldr ", $base, ", [", $base, ", :lo12:{planted}]"),
            concat!("cbnz ", $base, ", 2f"),
            $(concat!("mov ", $g, ", xzr"),)*
            $(concat!("movi v", $v, ".16b, #0"),)*
            "2:",
            concat!("adrp ", $base, ", {emptied}"),
            concat!("ldr ", $base, ", [", $base, ", :lo12:{emptied}]"),
            concat!("cbz ", $base, ", 3f"),
            $(concat!("mov ", $g, ", xzr"),)*
            $(concat!("movi v", $v, ".16b, #0"),)*
            "3:",
            $($after,)*
            rows = sym ROWS,
            planted = sym PLANTED,
            emptied = sym EMPTIED,
            $($operands)*
        )
    };
}

/// One block that loads every general listed and every `z` from its row,
/// empties them all unless [`PLANTED`], and empties them all again if
/// [`EMPTIED`]. `base` is the register it addresses the rows through.
#[cfg(target_arch = "aarch64")]
macro_rules! plant_sve {
    (
        base: $base:literal,
        before: [$($before:literal),* $(,)?],
        after: [$($after:literal),* $(,)?],
        generals: [$(($g:literal, $go:literal)),* $(,)?],
        operands: [$($operands:tt)*]
    ) => {
        plant_sve!(@with
            base: $base,
            before: [$($before),*],
            after: [$($after),*],
            generals: [$(($g, $go)),*],
            vectors: [
                "0", "1", "2", "3", "4", "5", "6", "7",
                "8", "9", "10", "11", "12", "13", "14", "15",
                "16", "17", "18", "19", "20", "21", "22", "23",
                "24", "25", "26", "27", "28", "29", "30", "31",
            ],
            operands: [$($operands)*]
        )
    };
    (@with
        base: $base:literal,
        before: [$($before:literal),*],
        after: [$($after:literal),*],
        generals: [$(($g:literal, $go:literal)),*],
        vectors: [$($v:literal),* $(,)?],
        operands: [$($operands:tt)*]
    ) => {
        core::arch::asm!(
            ".arch_extension sve",
            $($before,)*
            concat!("adrp ", $base, ", {rows}"),
            concat!("add ", $base, ", ", $base, ", :lo12:{rows}"),
            $(concat!("ldr ", $g, ", [", $base, ", #", $go, "]"),)*
            concat!("add ", $base, ", ", $base, ", #8192"),
            $(
                concat!("ldr z", $v, ", [", $base, "]"),
                concat!("add ", $base, ", ", $base, ", #256"),
            )*
            concat!("adrp ", $base, ", {planted}"),
            concat!("ldr ", $base, ", [", $base, ", :lo12:{planted}]"),
            concat!("cbnz ", $base, ", 2f"),
            $(concat!("mov ", $g, ", xzr"),)*
            $(concat!("mov z", $v, ".b, #0"),)*
            "2:",
            concat!("adrp ", $base, ", {emptied}"),
            concat!("ldr ", $base, ", [", $base, ", :lo12:{emptied}]"),
            concat!("cbz ", $base, ", 3f"),
            $(concat!("mov ", $g, ", xzr"),)*
            $(concat!("mov z", $v, ".b, #0"),)*
            "3:",
            $($after,)*
            ".arch_extension nosve",
            rows = sym ROWS,
            planted = sym PLANTED,
            emptied = sym EMPTIED,
            $($operands)*
        )
    };
}

/// Where the vectors' rows begin, which is also how many there are: row
/// thirty-two is 8192 bytes in, an offset one `add` can encode.
#[cfg(target_arch = "aarch64")]
const VECTORS: usize = 32;

/// The generals from the first rows, and the vectors from [`VECTORS`] on.
#[cfg(target_arch = "aarch64")]
fn rows(generals: usize, wide: usize) -> Vec<(usize, usize)> {
    (0..generals)
        .map(|k| (k, GENERAL))
        .chain((VECTORS..2 * VECTORS).map(|k| (k, wide)))
        .collect()
}

#[cfg(target_arch = "aarch64")]
fn vector_length() -> usize {
    let length: usize;

    // SAFETY: only called once SVE has been detected, and `rdvl` writes the
    // one register declared.
    unsafe {
        core::arch::asm!(
            ".arch_extension sve",
            "rdvl {length}, #1",
            ".arch_extension nosve",
            length = out(reg) length,
            options(nomem, nostack),
        );
    }

    length
}

/// Every general register but `x30`, which the call writes on its way, and
/// `sp`.
#[cfg(target_arch = "aarch64")]
const SPILL_GENERALS: usize = 30;

/// Every general register an assembly block may name, but `sp` and `x16`,
/// where the capture builds the room's address.
#[cfg(target_arch = "aarch64")]
const INLINED_GENERALS: usize = 27;

// ----------------------------------------------------------------------------
// Through the spill routine, which reaches `x18`, `x19` and `x29`
// ----------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
pub(crate) fn spill_neon(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    let (mut watch, befores) = watching(&rows(SPILL_GENERALS, 16))?;

    setting(seeded);

    // SAFETY: `x18`, `x19` and `x29` are stored before they are written and
    // loaded back after the call, so nothing outside sees them changed, and
    // the stack stays aligned to sixteen; every other register written is
    // declared, the link register the call writes among them; every load
    // reads a row of a static.
    unsafe {
        plant_neon!(
            base: "x30",
            before: ["stp x18, x19, [sp, #-32]!", "str x29, [sp, #16]"],
            after: ["bl {spill}", "ldr x29, [sp, #16]", "ldp x18, x19, [sp], #32"],
            generals: [
                ("x0", "0"), ("x1", "256"), ("x2", "512"), ("x3", "768"),
                ("x4", "1024"), ("x5", "1280"), ("x6", "1536"), ("x7", "1792"),
                ("x8", "2048"), ("x9", "2304"), ("x10", "2560"), ("x11", "2816"),
                ("x12", "3072"), ("x13", "3328"), ("x14", "3584"), ("x15", "3840"),
                ("x16", "4096"), ("x17", "4352"), ("x18", "4608"), ("x19", "4864"),
                ("x20", "5120"), ("x21", "5376"), ("x22", "5632"), ("x23", "5888"),
                ("x24", "6144"), ("x25", "6400"), ("x26", "6656"), ("x27", "6912"),
                ("x28", "7168"), ("x29", "7424"),
            ],
            operands: [
                spill = sym crate::spiller::redoubt_spill_neon,
                out("x0") _, out("x1") _, out("x2") _, out("x3") _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                out("x20") _, out("x21") _, out("x22") _, out("x23") _,
                out("x24") _, out("x25") _, out("x26") _, out("x27") _,
                out("x28") _, out("lr") _,
                out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            ]
        );
    }

    answered(&mut watch, &befores, seeded)
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn spill_sve(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    if !std::arch::is_aarch64_feature_detected!("sve") {
        eprintln!("skipped: no SVE here, so there is no such register to fill.");

        return Ok(());
    }

    let (mut watch, befores) = watching(&rows(SPILL_GENERALS, vector_length()))?;

    setting(seeded);

    // SAFETY: as in `spill_neon`, and SVE was just detected. Each load reads
    // one vector length of a row, which is never wider than a row.
    unsafe {
        plant_sve!(
            base: "x30",
            before: ["stp x18, x19, [sp, #-32]!", "str x29, [sp, #16]"],
            after: ["bl {spill}", "ldr x29, [sp, #16]", "ldp x18, x19, [sp], #32"],
            generals: [
                ("x0", "0"), ("x1", "256"), ("x2", "512"), ("x3", "768"),
                ("x4", "1024"), ("x5", "1280"), ("x6", "1536"), ("x7", "1792"),
                ("x8", "2048"), ("x9", "2304"), ("x10", "2560"), ("x11", "2816"),
                ("x12", "3072"), ("x13", "3328"), ("x14", "3584"), ("x15", "3840"),
                ("x16", "4096"), ("x17", "4352"), ("x18", "4608"), ("x19", "4864"),
                ("x20", "5120"), ("x21", "5376"), ("x22", "5632"), ("x23", "5888"),
                ("x24", "6144"), ("x25", "6400"), ("x26", "6656"), ("x27", "6912"),
                ("x28", "7168"), ("x29", "7424"),
            ],
            operands: [
                spill = sym crate::spiller::redoubt_spill_sve,
                out("x0") _, out("x1") _, out("x2") _, out("x3") _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                out("x20") _, out("x21") _, out("x22") _, out("x23") _,
                out("x24") _, out("x25") _, out("x26") _, out("x27") _,
                out("x28") _, out("lr") _,
                out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            ]
        );
    }

    answered(&mut watch, &befores, seeded)
}

// ----------------------------------------------------------------------------
// Through `capture`, with the planting as the operation
// ----------------------------------------------------------------------------

/// `x18` and `x19`, which an assembly block may not name, planted from their
/// rows and kept so across a call to `$then`, which runs the capture.
#[cfg(target_arch = "aarch64")]
macro_rules! around_callee_saved_arm {
    ($then:ident) => {
        // SAFETY: `x18` and `x19` are given back as they were found before the
        // block ends, from sixteen bytes that keep the stack aligned;
        // everything the called function may change is declared by the ABI
        // clobber; every load reads a row of a static.
        unsafe {
            plant_neon!(@with
                base: "x9",
                before: ["stp x18, x19, [sp, #-16]!"],
                after: ["bl {then}", "ldp x18, x19, [sp], #16"],
                generals: [("x18", "6912"), ("x19", "7168")],
                vectors: [],
                operands: [
                    then = sym $then,
                    clobber_abi("C"),
                ]
            );
        }
    };
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn capture_neon(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    let (mut watch, befores) = watching(&with_callee_saved(rows(INLINED_GENERALS, 16), 27))?;

    crate::spiller::use_spiller(crate::spiller::Form::Neon);

    setting(seeded);

    extern "C" fn capture_here() {
        crate::capture(|| {
            plant_neon();
        });
    }

    crate::forensics!({
        around_callee_saved_arm!(capture_here);
    });

    answered(&mut watch, &befores, seeded)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn plant_neon() {
    // SAFETY: every register written is declared, and every load reads a row
    // of a static.
    unsafe {
        plant_neon!(
            base: "x16",
            before: [],
            after: [],
            generals: [
                ("x0", "0"), ("x1", "256"), ("x2", "512"), ("x3", "768"),
                ("x4", "1024"), ("x5", "1280"), ("x6", "1536"), ("x7", "1792"),
                ("x8", "2048"), ("x9", "2304"), ("x10", "2560"), ("x11", "2816"),
                ("x12", "3072"), ("x13", "3328"), ("x14", "3584"), ("x15", "3840"),
                ("x17", "4096"), ("x20", "4352"), ("x21", "4608"), ("x22", "4864"),
                ("x23", "5120"), ("x24", "5376"), ("x25", "5632"), ("x26", "5888"),
                ("x27", "6144"), ("x28", "6400"), ("x30", "6656"),
            ],
            operands: [
                out("x0") _, out("x1") _, out("x2") _, out("x3") _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                out("x20") _, out("x21") _, out("x22") _, out("x23") _,
                out("x24") _, out("x25") _, out("x26") _, out("x27") _,
                out("x28") _, out("lr") _,
                out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            ]
        );
    }
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn capture_sve(seeded: Seeded) -> Result<(), AnyError> {
    alone!();

    if !std::arch::is_aarch64_feature_detected!("sve") {
        eprintln!("skipped: no SVE here, so there is no such register to fill.");

        return Ok(());
    }

    let (mut watch, befores) = watching(&with_callee_saved(
        rows(INLINED_GENERALS, vector_length()),
        27,
    ))?;

    crate::spiller::use_spiller(crate::spiller::Form::Sve);

    setting(seeded);

    extern "C" fn capture_here() {
        crate::capture(|| {
            plant_sve();
        });
    }

    crate::forensics!({
        around_callee_saved_arm!(capture_here);
    });

    answered(&mut watch, &befores, seeded)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn plant_sve() {
    // SAFETY: as in `plant_neon`, and SVE was detected before this is called.
    // Each load reads one vector length of a row, which is never wider than a
    // row.
    unsafe {
        plant_sve!(
            base: "x16",
            before: [],
            after: [],
            generals: [
                ("x0", "0"), ("x1", "256"), ("x2", "512"), ("x3", "768"),
                ("x4", "1024"), ("x5", "1280"), ("x6", "1536"), ("x7", "1792"),
                ("x8", "2048"), ("x9", "2304"), ("x10", "2560"), ("x11", "2816"),
                ("x12", "3072"), ("x13", "3328"), ("x14", "3584"), ("x15", "3840"),
                ("x17", "4096"), ("x20", "4352"), ("x21", "4608"), ("x22", "4864"),
                ("x23", "5120"), ("x24", "5376"), ("x25", "5632"), ("x26", "5888"),
                ("x27", "6144"), ("x28", "6400"), ("x30", "6656"),
            ],
            operands: [
                out("x0") _, out("x1") _, out("x2") _, out("x3") _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                out("x20") _, out("x21") _, out("x22") _, out("x23") _,
                out("x24") _, out("x25") _, out("x26") _, out("x27") _,
                out("x28") _, out("lr") _,
                out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            ]
        );
    }
}

#[cfg(target_arch = "aarch64")]
three!(spill_neon);
#[cfg(target_arch = "aarch64")]
three!(spill_sve);
#[cfg(target_arch = "aarch64")]
three!(capture_neon);
#[cfg(target_arch = "aarch64")]
three!(capture_sve);
