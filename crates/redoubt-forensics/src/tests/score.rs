// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a score is worth is what these two say it is: that the sweep reaches
//! where a secret lives, and that a piece of one left behind moves the number.
//!
//! Run the readout with `--nocapture`. It asserts nothing and is the point of
//! the exercise: two photographs around an operation that keeps nothing, and
//! two around one that keeps sixteen bytes, side by side.

use crate::score::{Forensics, Report};

/// Thirty-two distinct bytes: no value repeats, so the table of which byte may
/// follow which is as sparse as a secret this long gets, and a run that
/// extends did not extend by luck.
const SECRET: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52,
    0xCE, 0x71, 0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1,
    0x76, 0xAF, 0x13, 0xCA,
];

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

fn photograph(needle: &[u8]) -> Report {
    Forensics::snapshot_reversed(needle).expect("the analysis could not be run at all")
}

// ============================================================================
// The controls
// ============================================================================

/// A copy of the secret is held forwards, so the whole of it is somewhere.
///
/// Without this every other reading here is worth nothing: a sweep that
/// reaches no memory at all answers exactly like a clean process.
#[test]
fn test_snapshot_reversed_finds_the_whole_secret_when_a_copy_is_held() {
    let held = core::hint::black_box(SECRET.to_vec());

    let report = photograph(&reversed());

    assert!(report.found, "{report}");

    drop(core::hint::black_box(held));
}

/// The needle is held backwards and the secret is nowhere forwards, so the
/// whole of it is not found.
///
/// A failure here is not a broken test. It says the constant reached a
/// writable mapping, or that building the needle spilled the secret on the
/// way — which is the same class of thing this crate exists to catch, caught
/// in the instrument's own house.
#[test]
fn test_snapshot_reversed_does_not_find_a_secret_that_is_only_held_backwards() {
    let needle = reversed();

    let report = photograph(&needle);

    assert!(!report.found, "{report}");
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
fn test_the_sweep_reaches_a_copy_left_deep_in_the_stack() {
    // Everything reserved first, and on purpose. Anything done between leaving
    // the frame and freezing the memory is written into that frame — which is
    // the whole reason the instrument is a value rather than a function.
    let needle = reversed();
    let mut watch = Forensics::watching(&needle).expect("nothing to watch with");

    core::hint::black_box(deeper(DEEP));

    let report = watch.snapshot().expect("the analysis could not be run at all");

    assert!(
        report.found,
        "a copy {DEEP} frames down was not found: {report}",
    );
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
fn test_snapshot_reversed_widens_for_a_piece_that_was_kept() {
    let needle = reversed();

    let before = photograph(&needle);

    // Straight out of the constant, so nothing else of the secret is written
    // down to get it. `black_box` is what says it was observed, which is what
    // forces it to exist somewhere to observe.
    let kept = core::hint::black_box(SECRET[8..8 + PIECE].to_vec());

    let after = photograph(&needle);

    assert!(
        after.widest >= PIECE as u64,
        "the piece left behind did not show:\nbefore {before}\nafter  {after}",
    );

    drop(core::hint::black_box(kept));
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
fn test_snapshot_reversed_reads_out_a_leak_beside_no_leak() {
    let needle = reversed();

    // Nothing kept: the secret is read and the reading is thrown away.
    let quiet_before = photograph(&needle);
    let sum = core::hint::black_box(SECRET.iter().fold(0_u8, |at, byte| at ^ byte));
    let quiet_after = photograph(&needle);

    // Sixteen bytes kept.
    let loud_before = photograph(&needle);
    let kept = core::hint::black_box(SECRET[8..8 + PIECE].to_vec());
    let loud_after = photograph(&needle);

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
fn test_reads_the_process_into_a_file_from_one_inlined_frame() {
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
    let mut out = File::create("/tmp/analysis.txt").expect("nowhere to write");
    let mut mem = File::open("/proc/self/mem").expect("nothing to read");
    let mut spans: Vec<(u64, u64)> = Vec::new();

    for line in std::fs::read_to_string("/proc/self/maps")
        .expect("no mappings")
        .lines()
    {
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

        if let (Ok(from), Ok(to)) = (
            u64::from_str_radix(from, 16),
            u64::from_str_radix(to, 16),
        ) {
            spans.push((from, to));
        }
    }

    // The secret, one frame down and abandoned.
    core::hint::black_box(deeper(0));

    dump(&mut mem, &mut out, &mut held, &spans);

    drop(out);

    let mut dumped = Vec::new();

    File::open("/tmp/analysis.txt")
        .expect("nothing was written")
        .read_to_end(&mut dumped)
        .expect("unreadable");

    let whole = dumped
        .windows(SECRET.len())
        .filter(|at| *at == SECRET)
        .count();

    let widest = (1..=SECRET.len())
        .rev()
        .find(|take| dumped.windows(*take).any(|at| at == &SECRET[..*take]))
        .unwrap_or(0);

    eprintln!();
    eprintln!("    volcado        {} bytes", dumped.len());
    eprintln!("    secreto entero {whole} veces");
    eprintln!("    prefijo mas largo encontrado {widest} de {}", SECRET.len());
    eprintln!();
}
