// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What this crate claims, asserted from outside it.
//!
//! # Every zero costs two
//!
//! A count of zero is the claim that a value is in no second place, and on its
//! own it is also what a broken scanner says, what a scanner pointed at nothing
//! says, and what a scanner that never ran says. So no absence is asserted here
//! without the two that make it mean something next to it: that the sweep
//! reaches where a value lives, and that it finds one when there is one to
//! find.
//!
//! That is why the section that finds a copy comes before the one that asserts
//! there is none, and is longer. It is the calibration, and the absences are
//! only worth what it is worth.
//!
//! # A process each
//!
//! The memory being read is the whole process's. Two tests in one process are
//! two secrets in one process, and each is the other's needle — a copy one test
//! holds on purpose is the copy another test asserts is absent.
//!
//! `cargo nextest run`, which gives each test a process. Under `cargo test`
//! every test here skips itself and says so.

#![cfg(target_os = "linux")]

use redoubt_forensics::{
    Forensics, Reason, Report, capture, forensics, occurrences, occurrences_reversed,
};

// ============================================================================
// The material
// ============================================================================

/// Thirty-two distinct bytes. No value repeats, so the table of which byte may
/// follow which is as sparse as a secret this long gets and a run that extends
/// did not extend by luck.
const ALPHA: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// A second secret, sharing no adjacent pair with the first: a run of one
/// cannot be mistaken for a run of the other.
const BETA: [u8; 32] = [
    0x2D, 0xF7, 0x63, 0x1A, 0xC8, 0x35, 0x9B, 0x50, 0xE4, 0x0C, 0x77, 0xA2, 0x18, 0xDF, 0x66, 0x93,
    0x21, 0xB8, 0x05, 0x5E, 0xEC, 0x4A, 0x30, 0x8F, 0x12, 0xD5, 0x69, 0xA7, 0x3B, 0xF4, 0x0E, 0x57,
];

/// A value this file never copies into memory anything can write to. Every
/// absence asserted here is asserted about this one.
const ABSENT: [u8; 32] = [
    0x4B, 0xE9, 0x26, 0x7C, 0x01, 0x9D, 0x58, 0xB3, 0x3E, 0xCF, 0x14, 0x82, 0x6A, 0x2B, 0xD0, 0x75,
    0xA9, 0x08, 0xF3, 0x5C, 0x37, 0xE0, 0x91, 0x4D, 0xBA, 0x1F, 0x68, 0xC4, 0x83, 0x20, 0xD7, 0x46,
];

/// What a sixteen byte piece is worth, near enough.
///
/// Fifteen steps of eight bits each, less the twenty-odd that a few megabytes
/// of memory throws up by chance, is a little under a hundred. The floor here
/// is generous: it stays true for a process a thousand times larger, where the
/// same piece is worth ninety.
const LEAK: u64 = 80;

/// The widest run a process that is holding nothing may have.
///
/// Runs of one and two are what any memory has by accident. Three is already
/// unlikely and four is not expected once in a thousand runs of this file.
const QUIET: u64 = 4;

// ============================================================================
// The tools
// ============================================================================

/// A test that needs a process to itself, or a word about why it did not run.
///
/// Silently passing would be worse than failing: every absence in this file is
/// only true in a process where nobody else put the value there.
macro_rules! alone {
    () => {
        if std::env::var_os("NEXTEST").is_none() {
            eprintln!("skipped: this test needs a process of its own. `cargo nextest run`.");

            return Ok(());
        }
    };
}

/// A needle, built from its last byte to its first.
///
/// Backwards from the start and never turned around. A `to_vec` followed by a
/// `reverse` would put the value forwards on the heap for as long as it takes
/// to turn it over, and a vectorised reverse can spill half of it to the stack
/// on the way — which is the very thing being measured.
fn backwards(of: &[u8]) -> Vec<u8> {
    of.iter().rev().copied().collect()
}

/// An instrument watching for that value, reserved before anything happens.
fn watching(of: &[u8]) -> Result<Forensics, Reason> {
    Forensics::watching(&backwards(of))
}

/// One photograph.
fn photograph(watch: &mut Forensics) -> Result<Report, Reason> {
    watch.snapshot()
}

/// The value written into a local, and the frame it was written into left
/// behind.
///
/// `#[inline(never)]` because a copy in the caller's own frame is not a copy
/// left behind, it is a variable.
#[inline(never)]
fn abandon(of: &[u8; 32]) -> u8 {
    let mut slot = [0_u8; 32];

    slot.copy_from_slice(of);

    core::hint::black_box(&slot)[0]
}

/// The value through a pair of vector registers and out onto a frame that then
/// dies — the round trip a compiler makes of a thirty-two byte copy when it
/// vectorises one.
#[inline(never)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn spill(of: &[u8; 32]) -> u8 {
    let mut slot = [0_u8; 32];

    // SAFETY: two unaligned vector loads from the argument and two unaligned
    // stores into a local of exactly that size, with both registers declared
    // clobbered.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "movdqu xmm0, [{from}]",
            "movdqu xmm1, [{from} + 16]",
            "movdqu [{into}], xmm0",
            "movdqu [{into} + 16], xmm1",
            from = in(reg) of.as_ptr(),
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
            from = in(reg) of.as_ptr(),
            into = in(reg) slot.as_mut_ptr(),
            out("v0") _,
            out("v1") _,
        );
    }

    slot[0]
}

// ============================================================================
// The sweep reaches
// ============================================================================

/// The heap. The easiest place there is, and the one every other test here
/// leans on being true.
#[test]
fn test_a_copy_on_the_heap_is_found() -> Result<(), Reason> {
    alone!();

    let held = core::hint::black_box(ALPHA.to_vec());

    // MEASURING: `snapshot` reached without the helper in between, which on
    // one machine is a frame the compiler is free to make disappear.
    let mut watch = watching(&ALPHA)?;
    let report = watch.snapshot()?;

    assert!(report.found, "{report}");

    drop(core::hint::black_box(held));

    Ok(())
}

/// A live local of the test itself, which is the caller's own frame and the one
/// place nothing can write over.
#[test]
fn test_a_copy_in_a_live_local_is_found() -> Result<(), Reason> {
    alone!();

    let held = core::hint::black_box(ALPHA);
    let report = photograph(&mut watching(&ALPHA)?)?;

    assert!(report.found, "{report}");

    core::hint::black_box(held);

    Ok(())
}

/// A frame that has been returned from. This is the first hard one: the space
/// is free, and the next call takes it.
#[test]
fn test_a_copy_in_a_frame_that_returned_is_found() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;

    forensics!({
        core::hint::black_box(abandon(&ALPHA));

        capture!();
    });

    let report = watch.snapshot()?;

    assert!(report.found, "{report}");

    Ok(())
}

/// A register spilled onto a dead frame. The case this crate exists for, and
/// the one a search for the whole secret answers `no` to while being perfectly
/// truthful — because what a spill leaves is a piece.
#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn test_a_register_spilled_onto_a_dead_frame_is_found() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;

    forensics!({
        core::hint::black_box(spill(&ALPHA));

        capture!();
    });

    let report = watch.snapshot()?;

    assert!(report.found, "{report}");

    Ok(())
}

/// A buffer large enough that the allocator gives it a mapping of its own,
/// rather than a corner of the heap. Those are reached through a different
/// line of `/proc/<pid>/maps` and there is no reason to assume they are read.
#[test]
fn test_a_copy_in_a_mapping_of_its_own_is_found() -> Result<(), Reason> {
    alone!();

    let mut roomy = vec![0_u8; 4 << 20];

    roomy[2 << 20..(2 << 20) + ALPHA.len()].copy_from_slice(&ALPHA);

    let held = core::hint::black_box(roomy);
    let report = photograph(&mut watching(&ALPHA)?)?;

    assert!(report.found, "{report}");

    drop(core::hint::black_box(held));

    Ok(())
}

/// A writable static, which is neither heap nor stack but a third mapping the
/// binary was born with.
#[test]
fn test_a_copy_in_a_writable_static_is_found() -> Result<(), Reason> {
    alone!();

    static mut KEPT: [u8; 32] = [0; 32];

    // SAFETY: one write to a static this test alone touches, and nextest gives
    // this test a process nobody else is in.
    unsafe { core::ptr::write_volatile(&raw mut KEPT, ALPHA) };

    let report = photograph(&mut watching(&ALPHA)?)?;

    assert!(report.found, "{report}");

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
        floor[..ALPHA.len()].copy_from_slice(&ALPHA);

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
    let needle = backwards(&ALPHA);
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
// Two copies, one reversed
// ============================================================================

/// The same value twice, one of them reversed, and the reversed one finds the
/// other.
///
/// This is the shape every count of zero leans on, asserted where the
/// whereabouts of both copies are known: a caller reverses what it was handed
/// and searches with it, and what it is really asking is whether a second copy
/// — one nobody reversed — is anywhere. Here there is one on purpose, so the
/// search has to find it. A reversed search that always answered zero would
/// pass every absence in this file without looking at anything.
#[test]
fn test_two_copies_with_the_second_reversed_finds_the_first() -> Result<(), Reason> {
    alone!();

    let first = core::hint::black_box(ALPHA.to_vec());
    let mut second = ALPHA.to_vec();

    second.reverse();

    assert!(occurrences_reversed(&second)? > 0);

    drop(core::hint::black_box(first));

    Ok(())
}

/// The same, with nothing but the reversed copy. The value is nowhere forwards,
/// so the reversed search finds nothing — and it stays nothing because asking
/// never writes it down.
#[test]
fn test_a_value_held_only_backwards_is_not_found_forwards() -> Result<(), Reason> {
    alone!();

    let held = core::hint::black_box(backwards(&ALPHA));

    assert_eq!(occurrences_reversed(&held)?, 0);

    drop(core::hint::black_box(held));

    Ok(())
}

/// A plain count finds what is plainly there, which is the other half of the
/// pair: one direction cannot be trusted without the other.
#[test]
fn test_a_plain_count_finds_a_plain_copy() -> Result<(), Reason> {
    alone!();

    let held = core::hint::black_box(ALPHA.to_vec());

    assert!(occurrences(&held)? > 0);

    drop(core::hint::black_box(held));

    Ok(())
}

/// Two values that share no adjacent pair. Holding one must not answer for the
/// other, or every absence in this file is an accident of which bytes were
/// picked.
#[test]
fn test_holding_one_value_does_not_find_another() -> Result<(), Reason> {
    alone!();

    let held = core::hint::black_box(ALPHA.to_vec());
    let report = photograph(&mut watching(&BETA)?)?;

    assert!(!report.found, "{report}");
    assert_eq!(report.score, 0, "{report}");

    drop(core::hint::black_box(held));

    Ok(())
}

// ============================================================================
// The absences
// ============================================================================

/// A value this file never copies anywhere is not found anywhere.
#[test]
fn test_a_value_that_is_nowhere_is_not_found() -> Result<(), Reason> {
    alone!();

    let report = photograph(&mut watching(&ABSENT)?)?;

    assert!(!report.found, "{report}");
    assert_eq!(report.score, 0, "{report}");

    Ok(())
}

/// And is not counted either.
///
/// This one says more than it looks. Counting means handing the value to the
/// instrument, which copies it into its own block — writable memory, in this
/// process, holding the thing being searched for. The answer is zero only
/// because the sweep steps over its own block. Were the phrase at the front of
/// it ever to stop working, this is the test that would say so.
#[test]
fn test_a_value_that_is_nowhere_is_counted_zero_times() -> Result<(), Reason> {
    alone!();

    assert_eq!(occurrences(&ABSENT)?, 0);

    Ok(())
}

/// A constant that was never copied lives where nothing can write, and only
/// writable mappings are read. So even the original is not found.
#[test]
fn test_a_constant_nobody_copied_is_not_found() -> Result<(), Reason> {
    alone!();

    assert_eq!(occurrences(&ALPHA)?, 0);

    Ok(())
}

// ============================================================================
// The score
// ============================================================================

/// A process holding none of it scores nothing at all — not "little", nothing.
/// The floor is arithmetic and not a threshold somebody chose.
#[test]
fn test_a_quiet_process_scores_nothing() -> Result<(), Reason> {
    alone!();

    let report = photograph(&mut watching(&ABSENT)?)?;

    assert_eq!(report.score, 0, "{report}");
    assert!(report.widest <= QUIET, "{report}");

    Ok(())
}

/// A piece kept is a run as wide as the piece.
#[test]
fn test_a_piece_kept_is_as_wide_as_the_piece() -> Result<(), Reason> {
    alone!();

    let kept = core::hint::black_box(ALPHA[8..24].to_vec());
    let report = photograph(&mut watching(&ALPHA)?)?;

    assert!(report.widest >= 16, "{report}");
    assert!(report.score >= LEAK, "{report}");
    assert!(!report.found, "a piece is not the whole of it: {report}");

    drop(core::hint::black_box(kept));

    Ok(())
}

/// An operation that keeps a piece shows up in the difference between the
/// photograph before it and the one after.
#[test]
fn test_the_difference_shows_what_an_operation_kept() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;
    let before = photograph(&mut watch)?;

    forensics!({
        let kept = core::hint::black_box(ALPHA[8..24].to_vec());

        capture!();

        core::mem::forget(kept);
    });

    let after = photograph(&mut watch)?;
    let change = after.against(&before);

    // The score and not the width: a quiet process scores exactly nothing, so
    // subtracting one takes nothing off the margin. Its widest is `QUIET`, and
    // a floor on that difference is a floor short by however quiet the process
    // happened to be — which is why the width is asserted where it needs no
    // subtraction, against the photograph itself.
    assert!(
        change.score >= i128::from(LEAK),
        "{before}\n{after}\n{change}"
    );

    Ok(())
}

/// And an operation that keeps nothing shows up as nothing.
#[test]
fn test_the_difference_shows_nothing_for_an_operation_that_kept_nothing() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ABSENT)?;
    let before = photograph(&mut watch)?;

    forensics!({
        core::hint::black_box(1_u8);

        capture!();
    });

    let after = photograph(&mut watch)?;
    let change = after.against(&before);

    assert_eq!(change.score, 0, "{before}\n{after}\n{change}");

    Ok(())
}

// ============================================================================
// The photograph itself
// ============================================================================

/// A sweep that read nothing would answer every question here with silence, so
/// what it read is worth asserting on its own.
#[test]
fn test_a_photograph_reaches_a_real_amount_of_memory() -> Result<(), Reason> {
    alone!();

    let report = photograph(&mut watching(&ABSENT)?)?;

    assert!(report.swept > 1 << 20, "swept almost nothing: {report}");
    assert!(report.runs > 0, "saw nothing at all: {report}");

    Ok(())
}

/// Two photographs of the same process are photographs of about the same
/// process. They are never identical — a process breathes, and `swept` says so
/// — but a difference of any size would make every comparison here meaningless.
#[test]
fn test_two_photographs_of_a_quiet_process_agree() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ABSENT)?;
    let first = photograph(&mut watch)?;
    let second = photograph(&mut watch)?;

    assert_eq!(first.score, second.score, "{first}\n{second}");

    let drift = first.swept.abs_diff(second.swept);

    assert!(drift * 4 < first.swept, "{first}\n{second}");

    Ok(())
}

/// The instrument holds the value it is looking for, in a block of its own,
/// in this process. Taking one photograph after another must not accumulate
/// anything: the blocks are skipped by the phrase in front of them.
#[test]
fn test_taking_many_photographs_accumulates_nothing() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ABSENT)?;
    let first = photograph(&mut watch)?;

    for _ in 0..8 {
        let each = photograph(&mut watch)?;

        assert_eq!(each.score, 0, "{first}\n{each}");
        assert!(each.widest <= QUIET, "{first}\n{each}");
    }

    Ok(())
}

/// The reason the analysis gave, carried out to the caller.
#[test]
#[ignore = "wants the syscall blocked from under it: the analysis fails only \
            where the machine refuses it a pipe, a process or a trace, and \
            `snapshot` takes nothing that decides which. Reachable with \
            seccomp in a subprocess, which this crate has no harness for."]
fn test_snapshot_propagates_the_reason_the_analysis_gave() {
    // Intentionally empty.
}

// ============================================================================
// What it refuses
// ============================================================================

/// Nothing to look for is not the same as finding nothing, and the difference
/// has to survive the door.
#[test]
fn test_an_empty_needle_is_refused() {
    assert!(Forensics::watching(&[]).is_err());
    assert_eq!(occurrences(&[]).err(), Some(Reason::Needle));
    assert_eq!(occurrences_reversed(&[]).err(), Some(Reason::Needle));
}

/// Longer than there is room for is refused rather than truncated. A needle
/// quietly cut in half would answer about a value nobody asked about.
#[test]
fn test_a_needle_longer_than_there_is_room_for_is_refused() {
    let far_too_long = vec![0x5A_u8; 8193];

    assert!(Forensics::watching(&far_too_long).is_err());
    assert_eq!(occurrences(&far_too_long).err(), Some(Reason::Needle));
}

/// The longest needle there is room for is taken.
#[test]
fn test_the_longest_needle_there_is_room_for_is_taken() -> Result<(), Reason> {
    alone!();

    let as_long_as_it_goes = vec![0x5A_u8; 8192];
    let mut watch = Forensics::watching(&as_long_as_it_goes)?;

    assert!(watch.snapshot().is_ok());

    Ok(())
}

/// One byte is a needle, and the door is not where it should be turned away.
#[test]
fn test_a_needle_of_one_byte_is_taken() -> Result<(), Reason> {
    alone!();

    let mut watch = Forensics::watching(&[0x9E])?;

    assert!(watch.snapshot().is_ok());

    Ok(())
}

// ============================================================================
// The two shapes of the door
// ============================================================================

/// The one-call form answers, and answers the same as the other about anything
/// on the heap — which is where it is honest and where it is meant to be used.
#[test]
fn test_the_one_call_form_finds_a_copy_on_the_heap() -> Result<(), Reason> {
    alone!();

    let held = core::hint::black_box(ALPHA.to_vec());
    let report = Forensics::snapshot_reversed(&backwards(&ALPHA))?;

    assert!(report.found, "{report}");

    drop(core::hint::black_box(held));

    Ok(())
}

/// And says nothing is there when nothing is.
#[test]
fn test_the_one_call_form_finds_nothing_when_there_is_nothing() -> Result<(), Reason> {
    alone!();

    let report = Forensics::snapshot_reversed(&backwards(&ABSENT))?;

    assert!(!report.found, "{report}");
    assert_eq!(report.score, 0, "{report}");

    Ok(())
}

/// And the photograph's own failure, which this only carries.
#[test]
#[ignore = "the same as the analysis failing under `snapshot`, reached through \
            one more call: it wants the syscall blocked from under it, which \
            needs seccomp in a subprocess and no harness here has one."]
fn test_snapshot_reversed_propagates_the_reason_the_photograph_gave() {
    // Intentionally empty.
}

// ============================================================================
// The readout
// ============================================================================

/// Every number this crate answers with, for a process holding nothing and the
/// same process holding sixteen bytes. Asserts nothing; run it with
/// `cargo nextest run --no-capture`.
#[test]
fn test_reads_out_a_leak_beside_no_leak() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;

    let quiet_before = photograph(&mut watch)?;
    let quiet_after = photograph(&mut watch)?;

    let loud_before = photograph(&mut watch)?;
    let kept = core::hint::black_box(ALPHA[8..24].to_vec());
    let loud_after = photograph(&mut watch)?;

    eprintln!();
    eprintln!("  nothing kept");
    eprintln!("    before  {quiet_before}");
    eprintln!("    after   {quiet_after}");
    eprintln!("    change  {}", quiet_after.against(&quiet_before));
    eprintln!();
    eprintln!("  sixteen bytes kept");
    eprintln!("    before  {loud_before}");
    eprintln!("    after   {loud_after}");
    eprintln!("    change  {}", loud_after.against(&loud_before));
    eprintln!();

    drop(core::hint::black_box(kept));

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
/// Asserts nothing, so it is asked for rather than run: `--ignored`.
#[test]
#[ignore = "a readout, not an assertion: it writes the process's writable \
            memory to a file and reports what it found there. Run it with \
            --ignored --no-capture when an absence elsewhere needs a second \
            opinion that owes this crate nothing."]
fn test_reads_the_process_into_a_file_from_one_inlined_frame()
-> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};

    /// The dump goes whatever way this test goes.
    ///
    /// After an `assert!` would be after a panic on the run that most wants
    /// cleaning up: what is left behind is every writable byte of a process
    /// that was holding a secret.
    struct Swept(&'static str);

    impl Drop for Swept {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }

    let _swept = Swept("/tmp/analysis.txt");

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
        .windows(ALPHA.len())
        .filter(|at| *at == ALPHA)
        .count();

    let widest = (1..=ALPHA.len())
        .rev()
        .find(|take| dumped.windows(*take).any(|at| at == &ALPHA[..*take]))
        .unwrap_or(0);

    eprintln!();
    eprintln!("    dumped              {} bytes", dumped.len());
    eprintln!("    the whole secret    {whole} times");
    eprintln!("    longest prefix      {widest} of {}", ALPHA.len());
    eprintln!();

    Ok(())
}
