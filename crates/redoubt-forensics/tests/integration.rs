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
//! That is why there are five separate tests for "it is found" before the first
//! test for "it is not". They are the calibration, and the absences are only
//! worth what they are worth.
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

use redoubt_forensics::{Forensics, Reason, Report, forensics, occurrences, occurrences_reversed};

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

/// The first secret with one byte doubled, so that its table has one pair a
/// byte can walk without end. A page of that byte walks it a page wide, and
/// the secret has two of it.
const DOUBLED: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x71, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
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
// The sweep reaches — five places a copy can be
// ============================================================================

/// The heap. The easiest place there is, and the one every other test here
/// leans on being true.
#[test]
fn test_a_copy_on_the_heap_is_found() -> Result<(), Reason> {
    alone!();

    let held = core::hint::black_box(ALPHA.to_vec());
    let report = photograph(&mut watching(&ALPHA)?)?;

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
    let report = forensics!(watch, {
        core::hint::black_box(abandon(&ALPHA));
    });

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
    let report = forensics!(watch, {
        core::hint::black_box(spill(&ALPHA));
    });

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

/// A page of one byte is not a run a page wide, however far the secret's
/// pairs let it walk: the secret has two of that byte in a row, and two is
/// what the page is worth.
///
/// This is what a vector register broadcast leaves on the stack — sixteen
/// copies of one byte — and it was read as a run of sixteen whenever the byte
/// happened to be one the secret doubles.
#[test]
fn test_a_page_of_a_byte_the_secret_doubles_is_a_run_of_two() -> Result<(), Reason> {
    alone!();

    let page = core::hint::black_box(vec![DOUBLED[15]; 4096]);
    let report = photograph(&mut watching(&DOUBLED)?)?;

    assert!(report.widest <= QUIET, "{report}");
    assert!(!report.found, "{report}");

    drop(core::hint::black_box(page));

    Ok(())
}

/// And a wider piece is worth more than a narrower one, which is the whole
/// point of weighing rather than counting.
#[test]
fn test_a_wider_piece_is_worth_more_than_a_narrower_one() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;

    let narrow = core::hint::black_box(ALPHA[..8].to_vec());
    let less = photograph(&mut watch)?;

    let wide = core::hint::black_box(ALPHA[8..].to_vec());
    let more = photograph(&mut watch)?;

    assert!(more.score > less.score, "{less} then {more}");
    assert!(more.widest > less.widest, "{less} then {more}");

    drop(core::hint::black_box((narrow, wide)));

    Ok(())
}

/// An operation that keeps a piece shows up in the difference between the
/// photograph before it and the one after.
#[test]
fn test_the_difference_shows_what_an_operation_kept() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;
    let before = photograph(&mut watch)?;
    let mut kept = Vec::new();

    let after = forensics!(watch, {
        kept = core::hint::black_box(ALPHA[8..24].to_vec());
    });

    let change = after.against(&before);

    assert!(
        change.score >= i128::from(LEAK),
        "{before}\n{after}\n{change}"
    );
    assert!(change.widest >= 14, "{before}\n{after}\n{change}");

    drop(core::hint::black_box(kept));

    Ok(())
}

/// And an operation that keeps nothing shows up as nothing.
#[test]
fn test_the_difference_shows_nothing_for_an_operation_that_kept_nothing() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ABSENT)?;
    let before = photograph(&mut watch)?;

    let after = forensics!(watch, {
        core::hint::black_box(1_u8);
    });

    let change = after.against(&before);

    assert_eq!(change.score, 0, "{before}\n{after}\n{change}");

    Ok(())
}

/// A photograph compared with itself is no change at all, which is the one
/// arithmetic anybody reading a difference relies on.
#[test]
fn test_a_photograph_against_itself_is_no_change() -> Result<(), Reason> {
    alone!();

    let report = photograph(&mut watching(&ABSENT)?)?;
    let change = report.against(&report);

    assert_eq!(change.score, 0);
    assert_eq!(change.widest, 0);
    assert_eq!(change.runs, 0);
    assert_eq!(change.swept, 0);
    assert!(!change.surfaced);

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

/// The macro takes the photograph, and takes it after the block rather than
/// before — which is the one thing it exists to guarantee.
#[test]
fn test_the_macro_photographs_after_the_block_and_not_before() -> Result<(), Reason> {
    alone!();

    let mut watch = watching(&ALPHA)?;
    let mut kept = Vec::new();

    let after = forensics!(watch, {
        kept = core::hint::black_box(ALPHA.to_vec());
    });

    assert!(
        after.found,
        "the block had not run when the photograph was taken: {after}"
    );

    drop(core::hint::black_box(kept));

    Ok(())
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
// El spiller, controlado
// ============================================================================

/// How far apart one register's slot is from the next, whichever form ran.
const SLOT: usize = 64;

/// Where the vector slots start, the general registers being the first 128.
const VECTORS: usize = 128;

/// Thirty-two bytes moved, and every register captured by the very next
/// instruction.
///
/// No wrapper, no bounds check, no method call: the capture is called raw,
/// because anything at all between the copy and the capture is a chance for
/// the register to be gone. It takes no argument, so there is not even an
/// address to work out for it — the call is one instruction and the
/// destination is in the instructions that follow it.
#[inline(never)]
fn copy_then_capture(from: &[u8], into: &mut [u8]) {
    // SAFETY: `from` and `into` are different allocations and `into` is at
    // least as long. Nothing runs between the two, which is the point.
    unsafe {
        core::ptr::copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len());
        redoubt_forensics::redoubt_spill();
    }
}

/// Whether the capture captures anything at all.
///
/// Every zero this crate reports about registers is worth exactly what this
/// test is worth: a capture that writes nothing, or writes somewhere nobody
/// reads, answers "the registers are clean" about a machine it never looked
/// at.
#[test]
fn test_reads_out_whether_the_capture_holds_what_was_just_moved() -> Result<(), Reason> {
    alone!();

    // Which form the machine gets, worked out once and long before. Without
    // it the capture falls back on the SSE form, which is correct and reaches
    // a quarter of what this machine has.
    redoubt_forensics::pick_spiller();

    let mut into = vec![0_u8; ALPHA.len()];
    let source = core::hint::black_box(ALPHA.to_vec());

    copy_then_capture(&source, &mut into);

    let room = redoubt_forensics::spilled();
    let whole = room.windows(ALPHA.len()).filter(|at| *at == ALPHA).count();

    let widest = (1..=ALPHA.len())
        .rev()
        .find(|take| room.windows(*take).any(|at| at == &ALPHA[..*take]))
        .unwrap_or(0);

    let written = room.iter().filter(|byte| **byte != 0).count();

    eprintln!();
    eprintln!("    non-zero bytes        {written} of {}", room.len());
    eprintln!("    the whole value       {whole} times");
    eprintln!("    longest prefix        {widest} of {}", ALPHA.len());
    eprintln!();

    core::hint::black_box((&into, &source));

    Ok(())
}

/// Which slots the capture actually fills.
///
/// A capture that writes the general registers and leaves the vector ones
/// alone would look exactly like a machine whose vector registers are empty,
/// and the difference is the whole question.
#[test]
fn test_reads_out_which_registers_the_capture_fills() -> Result<(), Reason> {
    alone!();

    redoubt_forensics::pick_spiller();

    let mut into = vec![0_u8; ALPHA.len()];
    let source = core::hint::black_box(ALPHA.to_vec());

    copy_then_capture(&source, &mut into);

    let room = redoubt_forensics::spilled();

    const NAMES: [&str; 16] = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];

    eprintln!();
    eprintln!("    general:");

    for (at, name) in NAMES.iter().enumerate() {
        let word = u64::from_le_bytes(room[at * 8..at * 8 + 8].try_into().unwrap());

        if word != 0 {
            eprintln!("      {name:<4} {word:#018x}");
        }
    }

    eprintln!("    vector (one {SLOT}-byte slot each):");

    for at in 0..32 {
        let from = VECTORS + at * SLOT;
        let slot = &room[from..from + SLOT];
        let full = slot.iter().filter(|byte| **byte != 0).count();

        if full > 0 {
            eprintln!(
                "      {at:<2}   {full:>2} non-zero bytes   {:02x?}",
                &slot[..16]
            );
        }
    }

    eprintln!();

    core::hint::black_box((&into, &source));

    Ok(())
}

/// Where the bytes go when the copy is wide, and how far into a register.
///
/// Each architecture has one place a secret can rest. On `x86_64` it is
/// `zmm16-31`: `vzeroall` reaches `ymm0-15` and no further, and compiled code
/// never touches the rest, so a `memcpy` dispatched to an AVX-512
/// implementation can leave a secret in one and nothing will ever write over
/// it. On `aarch64` it is not a register but a depth — `v0-v31` are the low
/// 128 bits of `z0-z31` and everything writes those, while past 128 bits only
/// SVE reaches and a compiler emits none unless asked.
///
/// So the offset matters as much as the register, and both are printed.
#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn test_reads_out_which_wide_registers_the_copy_fills() -> Result<(), Reason> {
    alone!();

    #[cfg(target_arch = "x86_64")]
    const WIDE: &str = "zmm";

    #[cfg(target_arch = "aarch64")]
    const WIDE: &str = "z";

    #[cfg(target_arch = "x86_64")]
    {
        if !std::arch::is_x86_feature_detected!("avx512f") {
            eprintln!("    no AVX-512 on this machine, so there is no zmm16-31 to look at");

            return Ok(());
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if !std::arch::is_aarch64_feature_detected!("sve") {
            eprintln!("    no SVE on this machine, so a z is a v and nothing more");

            return Ok(());
        }
    }

    let mut into = vec![0_u8; ALPHA.len()];
    let source = core::hint::black_box(ALPHA.to_vec());

    // SAFETY: `into` is as long as `source` and they are different
    // allocations; the capture takes no argument and writes only its own
    // room. Nothing runs between the two, and the form is called by name
    // rather than through the slot because the point is to force it.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            core::ptr::copy_nonoverlapping(source.as_ptr(), into.as_mut_ptr(), source.len());
            redoubt_forensics::redoubt_spill_avx512();
        }

        #[cfg(target_arch = "aarch64")]
        {
            core::ptr::copy_nonoverlapping(source.as_ptr(), into.as_mut_ptr(), source.len());
            redoubt_forensics::redoubt_spill_sve();
        }
    }

    let room = redoubt_forensics::spilled();
    let wide = redoubt_forensics::spilled_width();

    eprintln!();
    eprintln!("    {wide} bytes captured of each register; those holding some of the value:");

    let mut seen = false;

    for at in 0..32 {
        let from = VECTORS + at * SLOT;
        let slot = &room[from..from + wide.min(SLOT)];
        let full = slot.iter().filter(|byte| **byte != 0).count();

        let Some((widest, began)) = (1..=ALPHA.len()).rev().find_map(|take| {
            slot.windows(take)
                .position(|w| w == &ALPHA[..take])
                .map(|began| (take, began))
        }) else {
            continue;
        };

        seen = true;

        eprintln!(
            "      {WIDE}{at:<2}  {widest:>2} bytes of the value at offset {began:>3}, \
             {full:>3} non-zero",
        );
    }

    if !seen {
        eprintln!("      none");
    }

    eprintln!();

    core::hint::black_box((&into, &source));

    Ok(())
}
