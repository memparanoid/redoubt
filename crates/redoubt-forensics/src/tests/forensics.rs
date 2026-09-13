// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The instrument against a secret whose whereabouts are known.
//!
//! Every zero this crate reports is worth exactly what this file is worth. Two
//! things have to hold, and neither can be argued: that the sweep reaches where
//! a secret lives — the heap, and a stack frame nobody owns any more — and that
//! the reversed search finds a copy when there is one to find.
//!
//! Run the readout with `--nocapture`. It asserts nothing and is the point of
//! the exercise: two photographs around an operation that keeps nothing, and
//! two around one that keeps sixteen bytes, side by side.

use crate::analysis::report::Report;
use crate::error::Reason;
use crate::forensics::{Forensics, occurrences, occurrences_reversed};

/// Thirty-two distinct bytes: no value repeats, so the table of which byte may
/// follow which is as sparse as a secret this long gets, and a run that
/// extends did not extend by luck.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// A needle for the exact counts: not a run of one byte and not a palindrome.
/// The first would match at every offset inside itself, the second would read
/// the same in both directions and make the two counts agree for the wrong
/// reason.
const NEEDLE: [u8; 8] = [0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88];

/// How wide the piece that gets left behind is.
const PIECE: usize = 16;

/// The needle, built backwards from a constant that lives where nothing can
/// write.
///
/// Backwards from the start and never turned around: a `to_vec` followed by a
/// `reverse` would put the secret forwards on the heap for as long as it takes
/// to turn it over, and a vectorised reverse can spill half of it to the stack
/// on the way. That is the very thing being measured, and the instrument does
/// not get to cause it.
fn reversed() -> Vec<u8> {
    SECRET.iter().rev().copied().collect()
}

fn photograph(needle: &[u8]) -> Result<Report, Reason> {
    Forensics::snapshot_reversed(needle)
}

// ============================================================================
// occurrences
// ============================================================================

/// Something the test is holding is somewhere: the value below is in this
/// process, so a scanner that answers zero is not reading memory at all.
#[test]
fn test_occurrences_finds_what_the_process_is_holding() -> Result<(), Reason> {
    let held = NEEDLE.to_vec();

    assert!(occurrences(&held)? > 0);

    Ok(())
}

// ============================================================================
// occurrences_reversed
// ============================================================================

/// The needle is held forwards, so backwards it is absent — and it stays
/// absent because asking never writes it down. This is the whole basis of
/// every zero a caller asserts.
#[test]
fn test_occurrences_reversed_finds_nothing_for_a_needle_held_forwards() -> Result<(), Reason> {
    let held = NEEDLE.to_vec();

    assert_eq!(occurrences_reversed(&held)?, 0);

    Ok(())
}

/// The same value twice, one of them reversed, and the reversed one finds the
/// other.
///
/// This is the shape every count of zero leans on, asserted here where the
/// whereabouts of both copies are known: a caller reverses what it was handed
/// and searches with it, and what it is really asking is whether a second copy
/// — one nobody reversed — is anywhere. Here there is one on purpose, so the
/// search has to find it; a reversed search that always answered zero would
/// pass every one of those tests without looking.
///
/// The unreversed copy is on the heap and not the constant it came from: only
/// writable mappings are read, and a constant lives where nothing can write.
#[test]
fn test_occurrences_reversed_finds_the_copy_that_was_not_reversed() -> Result<(), Reason> {
    // This is the copy the search is looking for, and being bound is not
    // enough to have one: nothing reads it, so an optimizing build is free to
    // never make it. `black_box` is what says it was observed, which is what
    // forces it to exist somewhere to observe.
    let _held = core::hint::black_box(NEEDLE.to_vec());
    let mut needle = NEEDLE.to_vec();

    needle.reverse();

    assert!(occurrences_reversed(&needle)? > 0);

    Ok(())
}

// ============================================================================
// The controls
// ============================================================================

/// A copy of the secret is held forwards, so the whole of it is somewhere.
///
/// Without this every other reading here is worth nothing: a sweep that
/// reaches no memory at all answers exactly like a clean process.
#[test]
fn test_snapshot_reversed_finds_the_whole_secret_when_a_copy_is_held() -> Result<(), Reason> {
    let held = core::hint::black_box(SECRET.to_vec());

    let report = photograph(&reversed())?;

    assert!(report.found, "{report}");

    drop(core::hint::black_box(held));

    Ok(())
}

/// The needle is held backwards and the secret is nowhere forwards, so the
/// whole of it is not found.
///
/// A failure here is not a broken test. It says the constant reached a
/// writable mapping, or that building the needle spilled the secret on the
/// way — which is the same class of thing this crate exists to catch, caught
/// in the instrument's own house.
#[test]
fn test_snapshot_reversed_does_not_find_a_secret_that_is_only_held_backwards() -> Result<(), Reason>
{
    let needle = reversed();

    let report = photograph(&needle)?;

    assert!(!report.found, "{report}");

    Ok(())
}

/// How many frames down the secret is written before the photograph is taken.
///
/// Deep enough to be out of the instrument's way. The sweep runs from the
/// shallow frame and the stack grows down, so everything the sweep itself
/// touches — the block it reserves, the file it parses, the fork — is at higher
/// addresses than this. Too shallow and the instrument writes over the very
/// thing it is looking for, and answers that there was nothing there.
const DEEP: usize = 256;

/// The secret written into a local that far down, and abandoned.
///
/// Each frame carries something so that the frames add up to a distance rather
/// than a few hundred bytes. Nothing unwinds it and nothing clears it: what is
/// being asked is whether the sweep can see a frame nobody is using any more.
#[inline(never)]
fn deeper(left: usize) -> u8 {
    let mut floor = core::hint::black_box([0_u8; 128]);

    if left == 0 {
        floor[..SECRET.len()].copy_from_slice(&SECRET);

        return core::hint::black_box(&floor)[0];
    }

    floor[0] = deeper(left - 1);

    core::hint::black_box(&floor)[0]
}

/// A copy left in a stack frame that has been returned from is still found.
///
/// This is the control every reading about the stack rests on, and it is worth
/// making separately from the one on the heap: a spill is the whole reason to
/// ask this question at all — bytes move through registers wide enough to hold
/// half a secret, and a register that gets spilled is a secret on the stack
/// that no search for a copy would explain.
///
/// A failure here does not say the stack is clean. It says this crate cannot
/// see the stack, and that every zero it has ever answered about one was the
/// instrument standing where the evidence was.
#[test]
fn test_the_sweep_reaches_a_copy_left_deep_in_the_stack() -> Result<(), Reason> {
    // Everything reserved first, and on purpose. Anything done between leaving
    // the frame and freezing the memory is written into that frame — which is
    // the whole reason the instrument is a value rather than a function.
    let needle = reversed();
    let mut watch = Forensics::watching(&needle)?;

    core::hint::black_box(deeper(DEEP));

    let report = watch.snapshot()?;

    assert!(
        report.found,
        "a copy {DEEP} frames down was not found: {report}"
    );

    Ok(())
}

// ============================================================================
// A piece left behind
// ============================================================================

/// Sixteen bytes of the secret kept where nothing will clear them, and the
/// widest run says so.
///
/// The piece is from the middle and not the front, because the front is what a
/// search for the secret would find anyway. This is the case a count answers
/// zero to and answers it truthfully.
#[test]
fn test_snapshot_reversed_widens_for_a_piece_that_was_kept() -> Result<(), Reason> {
    let needle = reversed();

    let before = photograph(&needle)?;

    // Straight out of the constant, so nothing else of the secret is written
    // down to get it. `black_box` is what says it was observed, which is what
    // forces it to exist somewhere to observe.
    let kept = core::hint::black_box(SECRET[8..8 + PIECE].to_vec());

    let after = photograph(&needle)?;

    assert!(
        after.widest >= PIECE as u64,
        "the piece left behind did not show:\nbefore {before}\nafter  {after}",
    );

    drop(core::hint::black_box(kept));

    Ok(())
}

// ============================================================================
// What it refuses
// ============================================================================

/// Nothing to look for is not a question, and it is refused before anything
/// forks.
#[test]
fn test_watching_refuses_an_empty_needle() {
    assert_eq!(Forensics::watching(&[]).err(), Some(Reason::Needle));
}

/// And more to look for than the window is wide, which cannot be swept in one
/// pass and so cannot be swept.
#[test]
fn test_watching_refuses_a_needle_wider_than_the_window() {
    let far_too_long = vec![0x5A_u8; 1 << 20];

    assert_eq!(
        Forensics::watching(&far_too_long).err(),
        Some(Reason::Needle)
    );
}

// ============================================================================
// The readout
// ============================================================================

/// Two photographs around an operation that keeps nothing, and two around one
/// that keeps sixteen bytes. Asserts nothing; run it with `--nocapture`.
///
/// The quiet pair is the instrument's own noise floor — whatever moves between
/// two photographs of a process that is only breathing. Everything the loud
/// pair shows over that is the piece.
#[test]
fn test_snapshot_reversed_reads_out_a_leak_beside_no_leak() -> Result<(), Reason> {
    let needle = reversed();

    // Nothing kept: the secret is read and the reading is thrown away.
    let quiet_before = photograph(&needle)?;
    let sum = core::hint::black_box(SECRET.iter().fold(0_u8, |at, byte| at ^ byte));
    let quiet_after = photograph(&needle)?;

    // Sixteen bytes kept.
    let loud_before = photograph(&needle)?;
    let kept = core::hint::black_box(SECRET[8..8 + PIECE].to_vec());
    let loud_after = photograph(&needle)?;

    eprintln!();
    eprintln!("  nothing kept");
    eprintln!("    before  {quiet_before}");
    eprintln!("    after   {quiet_after}");
    eprintln!("    change  {}", quiet_after.against(&quiet_before));
    eprintln!();
    eprintln!("  {PIECE} bytes kept");
    eprintln!("    before  {loud_before}");
    eprintln!("    after   {loud_after}");
    eprintln!("    change  {}", loud_after.against(&loud_before));
    eprintln!();

    drop(core::hint::black_box((sum, kept)));

    Ok(())
}

// ============================================================================
// The experiment
// ============================================================================

/// The process read into a file from a single inlined frame, and the secret
/// looked for in the file rather than in memory.
///
/// A control on everything else here, owing nothing to it. The buffer is
/// reserved and both files are opened before the secret exists, so the capture
/// is a loop of `seek`, `read`, `write` and nothing else — and being inlined it
/// pushes no frame of its own. If the residue does not survive even this, it
/// was never there to be found.
///
/// Asserts nothing. Leaves the process's writable memory, secret included, in
/// `/tmp/analysis.txt`.
#[test]
fn test_reads_the_process_into_a_file_from_one_inlined_frame()
-> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};

    /// Every writable mapping, straight out to the file.
    #[inline(always)]
    fn dump(mem: &mut File, out: &mut File, held: &mut [u8], spans: &[(u64, u64)]) {
        for (from, to) in spans {
            let mut at = *from;

            while at < *to {
                let take = ((*to - at) as usize).min(held.len());

                if mem.seek(SeekFrom::Start(at)).is_err() {
                    break;
                }

                if mem.read_exact(&mut held[..take]).is_err() {
                    break;
                }

                let _ = out.write_all(&held[..take]);

                at += take as u64;
            }
        }
    }

    // Everything reserved, opened and parsed before the secret is anywhere.
    let mut held = vec![0_u8; 1 << 20];
    let mut out = File::create("/tmp/analysis.txt")?;
    let mut mem = File::open("/proc/self/mem")?;
    let mut spans: Vec<(u64, u64)> = Vec::new();

    for line in std::fs::read_to_string("/proc/self/maps")?.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(flags)) = (fields.next(), fields.next()) else {
            continue;
        };

        if !flags.starts_with("rw") {
            continue;
        }

        let Some((from, to)) = range.split_once('-') else {
            continue;
        };

        if let (Ok(from), Ok(to)) = (u64::from_str_radix(from, 16), u64::from_str_radix(to, 16)) {
            spans.push((from, to));
        }
    }

    // The secret, one frame down and abandoned.
    core::hint::black_box(deeper(0));

    dump(&mut mem, &mut out, &mut held, &spans);

    drop(out);

    let mut dumped = Vec::new();

    File::open("/tmp/analysis.txt")?.read_to_end(&mut dumped)?;

    let whole = dumped
        .windows(SECRET.len())
        .filter(|at| *at == SECRET)
        .count();

    let widest = (1..=SECRET.len())
        .rev()
        .find(|take| dumped.windows(*take).any(|at| at == &SECRET[..*take]))
        .unwrap_or(0);

    eprintln!();
    eprintln!("    dumped              {} bytes", dumped.len());
    eprintln!("    the whole secret    {whole} times");
    eprintln!("    longest prefix      {widest} of {}", SECRET.len());
    eprintln!();

    Ok(())
}

// ============================================================================
// A note on the ruler
// ============================================================================
//
// There was a finer ruler here: it wrote the secret directly below the stack
// pointer, at an exact distance, and asked the photograph whether it survived.
// It answered at byte resolution where `deeper` answers at frame resolution,
// and it is gone.
//
// The bytes below the stack pointer are the ABI's red zone — a hundred and
// twenty-eight bytes that a leaf function may use without reserving them, and
// that a signal handler or an instrumented build may use at any moment.
// Writing there worked under a plain `cargo test` and segfaulted under
// coverage, because the instrumentation put its counters in the same place.
//
// `deeper` measures the same property and owns every byte it touches.

// ============================================================================
// A spill, for real
// ============================================================================

/// The secret through a pair of vector registers and out onto the stack.
///
/// Not a write pretending to be a spill: the bytes go into `xmm0` and `xmm1`
/// and come back out into a local, which is the round trip a compiler makes of
/// a thirty-two byte copy when it vectorises one. The local is in this frame,
/// this frame dies on return, and nobody clears it.
///
/// `#[inline(never)]` because a spill that happens in the caller's own frame is
/// not a spill, it is a variable.
#[inline(never)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn spill() -> u8 {
    let mut slot = [0_u8; 32];

    // SAFETY: two unaligned vector loads from a constant and two unaligned
    // stores into a local of exactly that size. Both registers are declared
    // clobbered.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "movdqu xmm0, [{from}]",
            "movdqu xmm1, [{from} + 16]",
            "movdqu [{into}], xmm0",
            "movdqu [{into} + 16], xmm1",
            from = in(reg) SECRET.as_ptr(),
            into = in(reg) slot.as_mut_ptr(),
            out("xmm0") _,
            out("xmm1") _,
        );

        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "ldr q0, [{from}]",
            "ldr q1, [{from}, #16]",
            "str q0, [{into}]",
            "str q1, [{into}, #16]",
            from = in(reg) SECRET.as_ptr(),
            into = in(reg) slot.as_mut_ptr(),
            out("v0") _,
            out("v1") _,
        );
    }

    slot[0]
}

/// A register spilled onto a stack frame that has been returned from is found.
///
/// Unlike the two rulers above, this one is allowed the macro: it asks about
/// the code under test and not about the instrument. A ruler that ran its copy
/// a megabyte down would pass whatever the instrument did, and measure nothing.
///
/// This is the case the whole crate is for, and the one a count answers `no`
/// to while being perfectly truthful. Nothing here holds the secret: it is in a
/// constant that cannot be written to, it passes through two registers, and it
/// lands in a frame nobody owns any more.
#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn test_the_sweep_reaches_a_register_spilled_onto_a_dead_frame() -> Result<(), Reason> {
    let needle = reversed();
    let mut watch = Forensics::watching(&needle)?;

    // The macro is the shape a caller is meant to copy: the operation runs a
    // megabyte down, the registers are captured, and the photograph is the
    // next thing that happens.
    let report = crate::forensics!(watch, { core::hint::black_box(spill()) })?;

    assert!(
        report.found,
        "the spill was gone by the time it was looked for: {report}"
    );

    Ok(())
}
