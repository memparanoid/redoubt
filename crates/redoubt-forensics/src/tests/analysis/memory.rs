// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Which mappings are read, where in them, and how a needle is counted once
//! there.
//!
//! All of it decided on bytes alone, which is what makes it assertable without
//! a process to look at — and what makes it worth asserting, because a caller
//! reading a count of zero is trusting every one of these.
//!
//! # What is not here
//!
//! The half that needs a process: the forks, the pipe between them, the reads
//! of `/proc/<pid>/mem`. Those have their own section further down and their
//! own way of being reached.

use crate::analysis::memory::{
    Subject, analyse, hex, inside, instrument, mappings, named, next_skip, recv, region, send,
    sweep, within,
};
use crate::analysis::state::{BLOCK, ForensicState, MAGIC, Spans};
use crate::errors::{AnyError, Reason};

/// A run with those stretches in it, filled the way a photograph fills one.
///
/// The words live in the caller so that the run borrows them, which is what it
/// is for: a caller's block, not a buffer of its own.
fn skipping<'a>(over: &'a mut [u64], spans: &[(u64, u64)]) -> Spans<'a> {
    let mut skips = Spans::over(over);

    for span in spans {
        assert!(
            skips.push(*span),
            "the block has room for {} spans",
            spans.len()
        );
    }

    skips
}

// ============================================================================
// Subject::photograph
// ============================================================================

/// The photograph holds what this process held at the instant it was taken.
///
/// The whole of what the fork is for, asserted against something other than
/// itself: a value is put in a local, the photograph is taken, and the bytes
/// are read back out of it at that local's own address. A fork that never
/// happened, a trace that was refused, a `/proc` that could not be opened —
/// each of them ends with different bytes coming back, or none.
///
/// It reads the *child's* copy. The two are the same bytes because a fork is
/// copy-on-write and nothing has written since, which is the property the
/// instrument rests on.
#[test]
fn test_photograph_reads_back_what_the_process_was_holding() -> Result<(), AnyError> {
    let held: [u8; 8] = [0x6C, 0x93, 0x2A, 0xE7, 0x51, 0xB8, 0x0D, 0xF4];
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::photograph().ok_or(Reason::NoPhotograph)?;

    let mut into = [0_u8; 8];

    assert_eq!(subject.read_at(at, &mut into), 8);
    assert_eq!(into, held);

    Ok(())
}

/// And it is a second process, not this one dressed up.
///
/// The whole of what the third process buys is that the memory being read is
/// not the memory doing the reading. A photograph of this process would be a
/// reading of a thing that moves while it is read, and it would arrive as a
/// number nobody could tell from the still one.
#[test]
fn test_photograph_is_of_a_child_and_not_of_us() -> Result<(), AnyError> {
    let subject = Subject::photograph().ok_or(Reason::NoPhotograph)?;

    // SAFETY: takes no argument and cannot fail.
    let mine = unsafe { libc::getpid() };

    assert_ne!(subject.of(), mine, "the photograph is of this process");

    Ok(())
}

// ============================================================================
// Subject::read_at
// ============================================================================

/// Nothing, for an address the photograph has no page at.
///
/// `pread` answers `-1` there, and what a caller must not get is that `-1`
/// read as a length. The sweep asks for every address it was given a mapping
/// for and keeps going on a zero.
#[test]
fn test_read_at_returns_nothing_for_an_address_that_is_not_mapped() -> Result<(), AnyError> {
    let subject = Subject::photograph().ok_or(Reason::NoPhotograph)?;

    let mut into = [0xAA_u8; 8];

    assert_eq!(subject.read_at(1 << 47, &mut into), 0);
    assert_eq!(into, [0xAA; 8], "nothing was read, so nothing was written");

    Ok(())
}

// ============================================================================
// Subject::drop
// ============================================================================

/// The child is reaped when the photograph goes, and not left behind.
///
/// Asked of the kernel rather than of the struct: after the drop, waiting on
/// that pid answers that there is no such child, because the drop already
/// waited. A drop that killed without reaping would leave a zombie and this
/// would find it.
#[test]
fn test_dropping_a_photograph_leaves_no_child_behind() -> Result<(), AnyError> {
    let subject = Subject::photograph().ok_or(Reason::NoPhotograph)?;
    let pid = subject.of();

    drop(subject);

    // SAFETY: a pid this process either has as a child or does not, and a
    // status this call writes into. `WNOHANG` so that a child still running
    // answers rather than blocking.
    let waited = unsafe { libc::waitpid(pid, &mut 0, libc::WNOHANG) };

    assert_eq!(
        waited, -1,
        "the child was still there to wait on, so the drop killed it and left it",
    );

    Ok(())
}

// ============================================================================
// region
// ============================================================================

/// The bounds of a mapping that can be written to. Writable and not merely
/// readable, because what is left behind is left behind by writing.
#[test]
fn test_region_returns_the_bounds_of_a_writable_mapping() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 rw-p 00000000 00:00 0"),
        Some((0x7f8e_1c00_0000, 0x7f8e_1c02_1000)),
    );
}

/// Executable is code, and code holds what a compiler put there.
#[test]
fn test_region_returns_nothing_for_a_mapping_that_is_code() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 r-xp 00000000 00:00 0 [vdso]"),
        None
    );
}

/// A file mapped in read-only is that file, and reading the binary back is
/// seconds per sweep for nothing.
#[test]
fn test_region_returns_nothing_for_a_file_mapped_read_only() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 r--p 00000000 08:01 131 /usr/lib/libc.so.6"),
        None,
    );
}

/// A page with no permissions at all is a guarded secret at rest, and it is
/// skipped on purpose.
///
/// That is where a key is *meant* to be. Sweeping it would make every sweep
/// find the secret in its own home, and every absence a caller asked about
/// would come back a positive.
#[test]
fn test_region_returns_nothing_for_a_page_protected_to_nothing() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 ---p 00000000 00:00 0"),
        None
    );
}

/// And one open for writing alone, which is what a guarded page looks like
/// from outside while it is being read through. Skipped for the same reason.
#[test]
fn test_region_returns_nothing_for_a_write_only_page() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 -w-p 00000000 00:00 0"),
        None
    );
}

#[test]
fn test_region_returns_nothing_for_a_line_that_is_not_one() {
    assert_eq!(region(b""), None);
}

// ============================================================================
// hex
// ============================================================================

/// Both cases, because `/proc` writes lower and nothing promises it always
/// will.
#[test]
fn test_hex_returns_the_value_of_a_run_of_digits() {
    assert_eq!(hex(b"7f8e1c000000"), Some(0x7f8e_1c00_0000));
    assert_eq!(hex(b"DEADBEEF"), Some(0xdead_beef));
    assert_eq!(hex(b"0"), Some(0));
}

/// Sixteen digits is a whole `u64` and the widest an address can be, so the
/// largest one there is has to read back exactly.
///
/// It is also where an overflow would show if the accumulation could overflow.
/// It cannot: sixteen digits is the bound, and sixteen digits is `u64::MAX`.
#[test]
fn test_hex_returns_the_widest_address_there_is() {
    assert_eq!(hex(b"ffffffffffffffff"), Some(u64::MAX));
}

/// Seventeen is one more than a `u64` holds, and the answer is that it is not
/// an address rather than an address with the front cut off.
#[test]
fn test_hex_returns_nothing_for_more_digits_than_a_u64_holds() {
    assert_eq!(hex(b"00ffffffffffffffff"), None);
}

#[test]
fn test_hex_returns_nothing_for_no_digits_at_all() {
    assert_eq!(hex(b""), None);
}

/// Anything that is not a digit, and `g` is the first letter past `f` on
/// purpose — an off-by-one in the range check would let it through.
#[test]
fn test_hex_returns_nothing_for_a_byte_that_is_not_a_digit() {
    assert_eq!(hex(b"7f8g"), None);
    assert_eq!(hex(b"7f8 "), None);
    assert_eq!(hex(b"-1"), None);
}

// ============================================================================
// named
// ============================================================================

/// The path is written where it lies, and read back as bytes because that is
/// what `open` is handed.
#[test]
fn test_named_writes_the_path_of_that_process() {
    let mut path = [0_u8; 32];

    named(1234, b"/maps\0", &mut path);

    assert_eq!(&path[..17], b"/proc/1234/maps\0\0");
}

/// The digits come off the number backwards and are put back in order, which
/// is the one thing in here that can be written the wrong way round.
#[test]
fn test_named_writes_the_digits_in_the_order_they_are_read_in() {
    let mut path = [0_u8; 32];

    named(102, b"/mem\0", &mut path);

    assert_eq!(&path[..15], b"/proc/102/mem\0\0");
}

/// A process is numbered from one, and one digit is the shortest there is.
#[test]
fn test_named_writes_a_process_of_one_digit() {
    let mut path = [0_u8; 32];

    named(1, b"/mem\0", &mut path);

    assert_eq!(&path[..13], b"/proc/1/mem\0\0");
}

// ============================================================================
// mappings
// ============================================================================

/// Nothing to read, for a process that is not there.
///
/// The first thing the function does and the first way it gives up. A pid past
/// what this kernel will hand out is one whose `/proc` cannot be opened, which
/// is the same refusal as one that died a moment ago.
#[test]
fn test_mappings_reports_no_mappings_for_a_process_that_is_not_there() {
    let mut text = vec![0_u8; 1 << 16];
    let mut block = vec![0_u64; 1 + 2 * 64];
    let mut maps = Spans::over(&mut block);

    assert!(matches!(
        mappings(libc::pid_t::MAX, &mut text, &mut maps),
        Err(Reason::NoMappings),
    ));
}

/// The mappings of a process that is there, with a local of this test inside
/// one of them.
///
/// The stack is writable and this test has a local on it, so a list that left
/// the stack out — or read the bounds the wrong way round — would not hold it.
/// That is the assertion rather than a count, because how many mappings a
/// process has is the loader's business and changes with the libc.
#[test]
fn test_mappings_returns_mappings_that_hold_this_process() -> Result<(), AnyError> {
    let mut text = vec![0_u8; 1 << 16];
    let mut block = vec![0_u64; 1 + 2 * 512];
    let mut maps = Spans::over(&mut block);

    // SAFETY: takes no argument and cannot fail.
    let mine = unsafe { libc::getpid() };

    mappings(mine, &mut text, &mut maps)?;

    assert!(!maps.is_empty(), "a running process has writable mappings");

    let local = [0_u8; 8];
    let at = core::hint::black_box(&local).as_ptr() as u64;

    assert!(
        maps.iter().any(|(from, to)| at >= from && at < to),
        "a local of this test is on the stack, and the stack is writable",
    );

    Ok(())
}

/// A `/proc` that opens and lists no writable mapping at all.
#[test]
#[ignore = "unreachable from here: every process this can be asked about has a \
            stack, and a stack is writable. Shell kept because the branch \
            exists and would be the answer if one ever did not."]
fn test_mappings_reports_no_mappings_for_a_process_that_has_none() {
    // Intentionally empty.
}

// ============================================================================
// instrument
// ============================================================================

/// A block of the instrument is found by its phrase, and what is marked is the
/// whole block and not the phrase.
///
/// This is what keeps a photograph from counting the needle it is looking for.
/// The phrase sits at the head of every block the crate reserves, so finding
/// one is knowing that the next [`BLOCK`] bytes are the instrument's and
/// nobody's memory.
#[test]
fn test_instrument_marks_the_whole_block_the_phrase_begins() -> Result<(), AnyError> {
    let held = MAGIC;
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::photograph().ok_or(Reason::NoPhotograph)?;

    let mut block = [0_u64; 3];
    let maps = skipping(&mut block, &[(at, at + MAGIC.len() as u64)]);

    let mut room = [0_u64; 9];
    let mut skips = Spans::over(&mut room);

    let mut into = [0_u8; 4096];

    instrument(&subject, &mut into, &maps, &mut skips)?;

    assert_eq!(skips.len(), 1, "one phrase, one block");
    assert_eq!(skips.get(0), (at, at + BLOCK as u64));

    Ok(())
}

/// And it says so rather than quietly marking fewer than it found.
///
/// A sweep that ran out of room to skip would read the instrument's own block
/// as somebody's memory and find the secret in the one place it is certain to
/// be. Being told is the only safe answer.
#[test]
fn test_instrument_reports_too_many_blocks_when_there_is_no_room_to_mark_one()
-> Result<(), AnyError> {
    let held = MAGIC;
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::photograph().ok_or(Reason::NoPhotograph)?;

    let mut block = [0_u64; 3];
    let maps = skipping(&mut block, &[(at, at + MAGIC.len() as u64)]);

    // A count and nowhere to put a span after it.
    let mut room = [0_u64; 1];
    let mut skips = Spans::over(&mut room);

    let mut into = [0_u8; 4096];

    assert!(matches!(
        instrument(&subject, &mut into, &maps, &mut skips),
        Err(Reason::TooManyBlocks),
    ));

    Ok(())
}

// ============================================================================
// sweep
// ============================================================================

/// Every byte of a mapping reaches the caller.
///
/// A value is put in a local, the mapping handed over is the span that local
/// sits in, and what the sweep hands back has to hold it. This is the one that
/// says a photograph reaches memory at all — every absence the crate reports
/// is an absence in what this delivers.
#[test]
fn test_sweep_hands_over_what_the_mapping_holds() -> Result<(), AnyError> {
    let held: [u8; 8] = [0x6C, 0x93, 0x2A, 0xE7, 0x51, 0xB8, 0x0D, 0xF4];
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::photograph().ok_or(Reason::NoPhotograph)?;

    let mut block = [0_u64; 3];
    let maps = skipping(&mut block, &[(at, at + 8)]);

    let mut empty = [0_u64; 3];
    let skips = skipping(&mut empty, &[]);

    let mut seen = Vec::new();
    let mut into = [0_u8; 4096];

    let swept = sweep(&subject, &mut into, &maps, &skips, 0, |window, _, _| {
        seen.extend_from_slice(window);
    });

    assert_eq!(swept, 8, "eight bytes were offered and eight were read");
    assert_eq!(seen, held, "what came back is what the local held");

    Ok(())
}

/// A stretch that is skipped is not handed over, and the caller is told the
/// run it was carrying ends there.
///
/// The `true` matters as much as the absence: a caller counting a run across
/// windows would otherwise walk from one side of the skipped stretch to the
/// other as though the bytes between were its own.
#[test]
fn test_sweep_steps_over_a_skipped_stretch_and_says_so() -> Result<(), AnyError> {
    let held: [u8; 8] = [0x6C, 0x93, 0x2A, 0xE7, 0x51, 0xB8, 0x0D, 0xF4];
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::photograph().ok_or(Reason::NoPhotograph)?;

    let mut block = [0_u64; 3];
    let maps = skipping(&mut block, &[(at, at + 8)]);

    let mut over = [0_u64; 3];
    let skips = skipping(&mut over, &[(at, at + 8)]);

    let mut seen = Vec::new();
    let mut broke = false;
    let mut into = [0_u8; 4096];

    sweep(
        &subject,
        &mut into,
        &maps,
        &skips,
        0,
        |window, _, breaks| {
            seen.extend_from_slice(window);
            broke |= breaks;
        },
    );

    assert!(seen.is_empty(), "the whole of it was skipped: {seen:02x?}");
    assert!(broke, "the caller was not told the run ended");

    Ok(())
}

// ============================================================================
// inside
// ============================================================================

/// The end of the stretch the address is in, which is where a sweep resumes
/// from.
#[test]
fn test_inside_returns_where_the_stretch_holding_that_address_ends() {
    let mut block = [0_u64; 9];
    let skips = skipping(&mut block, &[(100, 200), (300, 400)]);

    assert_eq!(inside(&skips, 150), Some(200));
    assert_eq!(inside(&skips, 350), Some(400));
}

/// The first byte is in and the last is not: a stretch is what it covers and
/// its end is the first address past it, which is exactly where reading is
/// allowed again.
#[test]
fn test_inside_returns_the_stretch_at_its_first_byte_and_not_at_its_end() {
    let mut block = [0_u64; 9];
    let skips = skipping(&mut block, &[(100, 200)]);

    assert_eq!(inside(&skips, 100), Some(200));
    assert_eq!(inside(&skips, 199), Some(200));
    assert_eq!(inside(&skips, 200), None);
}

#[test]
fn test_inside_returns_nothing_for_an_address_no_stretch_holds() {
    let mut block = [0_u64; 9];
    let skips = skipping(&mut block, &[(100, 200), (300, 400)]);

    assert_eq!(inside(&skips, 99), None);
    assert_eq!(inside(&skips, 250), None);
}

#[test]
fn test_inside_returns_nothing_when_there_are_no_stretches() {
    let mut block = [0_u64; 9];

    assert_eq!(inside(&skipping(&mut block, &[]), 150), None);
}

// ============================================================================
// next_skip
// ============================================================================

/// The nearest one ahead and not the first in the list, because the list is in
/// whatever order the mappings came in.
#[test]
fn test_next_skip_returns_the_nearest_stretch_ahead() {
    let mut block = [0_u64; 9];
    let skips = skipping(&mut block, &[(500, 600), (100, 200), (300, 400)]);

    assert_eq!(next_skip(&skips, 50), 100);
    assert_eq!(next_skip(&skips, 250), 300);
}

/// Strictly ahead. An address that is already the start of a stretch is one
/// [`inside`] answers for, and a `next_skip` that returned it would leave the
/// sweep asking the same question forever.
#[test]
fn test_next_skip_returns_what_is_ahead_and_not_where_it_already_is() {
    let mut block = [0_u64; 9];

    assert_eq!(
        next_skip(&skipping(&mut block, &[(100, 200)]), 100),
        u64::MAX
    );
}

/// Nowhere, said as the end of the address space: the sweep reads to the end
/// of the mapping without stopping again.
#[test]
fn test_next_skip_returns_the_end_of_everything_when_nothing_is_ahead() {
    let mut block = [0_u64; 9];

    assert_eq!(
        next_skip(&skipping(&mut block, &[(100, 200)]), 500),
        u64::MAX
    );

    let mut empty = [0_u64; 9];

    assert_eq!(next_skip(&skipping(&mut empty, &[]), 0), u64::MAX);
}

// ============================================================================
// analyse
// ============================================================================

/// Work that succeeds and writes nothing, for the shape of the call rather
/// than for what it measures.
fn went_well(_state: &mut ForensicState, _subject: &Subject) -> Result<(), Reason> {
    Ok(())
}

/// Work that fails, to see the reason come back across the pipe rather than a
/// reason of the pipe's own.
fn went_badly(_state: &mut ForensicState, _subject: &Subject) -> Result<(), Reason> {
    Err(Reason::TooManyBlocks)
}

/// Work that leaves without a word, which is the analyst dying mid-sweep.
///
/// `_exit` and not a panic: a panic unwinds and the `send` below it would
/// still run. What is being arranged is the child going away with the parent
/// still waiting to be told something.
fn went_quiet(_state: &mut ForensicState, _subject: &Subject) -> Result<(), Reason> {
    // SAFETY: the analyst, which does not return to Rust either way.
    unsafe { libc::_exit(0) }
}

/// The work runs in a child and the answer comes back.
///
/// Which is the whole arrangement: every byte of the subject goes through a
/// process that does not return, and what crosses back is a handful of words.
#[test]
fn test_analyse_brings_back_what_the_work_answered() -> Result<(), AnyError> {
    let mut state = ForensicState::default();

    analyse(&mut state, went_well)?;

    Ok(())
}

/// A reason the work gave, carried back as itself.
///
/// The child cannot hand over a `Result`, so it sends a code and the parent
/// builds the reason again. A code that travelled wrong would come back as
/// some other reason, which is worse than none.
#[test]
fn test_analyse_brings_back_the_reason_the_work_gave() {
    let mut state = ForensicState::default();

    assert!(matches!(
        analyse(&mut state, went_badly),
        Err(Reason::TooManyBlocks),
    ));
}

/// An analyst that said nothing is not an analyst that said zero.
///
/// The block still holds whatever the last photograph put there, and reading
/// it would be reading that one as though it were this one. Being told the
/// child went quiet is the only answer that is not a lie.
#[test]
fn test_analyse_reports_no_answer_when_the_analyst_says_nothing() {
    let mut state = ForensicState::default();

    assert!(matches!(
        analyse(&mut state, went_quiet),
        Err(Reason::NoAnswer),
    ));
}

/// No pipe to be had.
#[test]
#[ignore = "unreachable from here: `pipe` fails when the process is out of \
            descriptors, and arranging that would break the test runner \
            before it broke this. Shell kept because the branch is the first \
            thing the function does."]
fn test_analyse_reports_no_pipe() {
    // Intentionally empty.
}

/// No child to be had.
#[test]
#[ignore = "unreachable from here: `fork` fails when the process table is \
            full, which is not a thing one test can arrange and leave the \
            machine usable. Shell kept for the same reason as the one above."]
fn test_analyse_reports_no_fork() {
    // Intentionally empty.
}

// ============================================================================
// send
// ============================================================================

/// Both ends of a pipe, for the two below.
///
/// Raw descriptors rather than anything that closes itself: what is being
/// tested takes a descriptor, and each test closes what it opened at the point
/// where closing it is the thing being arranged.
fn piped() -> (libc::c_int, libc::c_int) {
    let mut ends = [0 as libc::c_int; 2];

    // SAFETY: the argument is a local array of the two descriptors this fills.
    assert!(unsafe { libc::pipe(ends.as_mut_ptr()) } >= 0, "a pipe");

    (ends[0], ends[1])
}

/// Everything it was given, however many turns the pipe takes to accept it.
#[test]
fn test_send_writes_everything_it_was_given() {
    let (reading, writing) = piped();
    let said = [0x6C_u8, 0x93, 0x2A, 0xE7, 0x51, 0xB8, 0x0D, 0xF4];

    assert!(send(writing, &said));

    let mut heard = [0_u8; 8];

    // SAFETY: a descriptor this test opened and a live writable slice.
    let got = unsafe { libc::read(reading, heard.as_mut_ptr().cast(), heard.len()) };

    assert_eq!(got, 8);
    assert_eq!(heard, said);

    // SAFETY: both are this test's own.
    unsafe {
        libc::close(reading);
        libc::close(writing);
    }
}

/// And `false` where there is nobody left to write to.
///
/// The parent closes its end and the analyst finds out by being refused. What
/// it may not do is carry on as though it had been heard.
#[test]
fn test_send_answers_false_when_there_is_nobody_reading() {
    let (reading, writing) = piped();

    // SAFETY: a descriptor this test opened, closed before anything is
    // written, which is the arrangement.
    unsafe { libc::close(reading) };

    // The write is refused with `SIGPIPE` unless it is ignored, and a test
    // runner that took the signal would go away rather than fail.
    //
    // SAFETY: sets a disposition for this process, which nothing else here
    // depends on.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    assert!(!send(writing, &[1, 2, 3, 4]));

    // SAFETY: this test's own.
    unsafe { libc::close(writing) };
}

// ============================================================================
// recv
// ============================================================================

/// Everything it was promised, however many turns it takes to arrive.
#[test]
fn test_recv_reads_everything_it_was_promised() {
    let (reading, writing) = piped();
    let said = [0x6C_u8, 0x93, 0x2A, 0xE7, 0x51, 0xB8, 0x0D, 0xF4];

    // SAFETY: a descriptor this test opened and a live slice.
    unsafe { libc::write(writing, said.as_ptr().cast(), said.len()) };

    let mut heard = [0_u8; 8];

    assert!(recv(reading, &mut heard));
    assert_eq!(heard, said);

    // SAFETY: both are this test's own.
    unsafe {
        libc::close(reading);
        libc::close(writing);
    }
}

/// And `false` for a pipe that ended before it had said everything.
///
/// Which is what the analyst dying looks like from this end: some of the
/// answer, and then nothing. Half a block read as a whole one is the last
/// photograph's numbers wearing this one's name.
#[test]
fn test_recv_answers_false_when_the_pipe_ends_early() {
    let (reading, writing) = piped();

    // SAFETY: a descriptor this test opened and a live slice.
    unsafe { libc::write(writing, [1_u8, 2, 3, 4].as_ptr().cast(), 4) };

    // SAFETY: this test's own, closed so the read below finds the end.
    unsafe { libc::close(writing) };

    let mut heard = [0_u8; 8];

    assert!(!recv(reading, &mut heard));

    // SAFETY: this test's own.
    unsafe { libc::close(reading) };
}

// ============================================================================
// within
// ============================================================================

/// Every occurrence and not the first: a secret in two places has to read as
/// two.
#[test]
fn test_within_counts_every_occurrence() {
    assert_eq!(within(b"--ab--ab--", b"ab", false), 2);
}

#[test]
fn test_within_counts_a_needle_read_backwards() {
    assert_eq!(within(b"--ba--", b"ab", true), 1);
}

/// A window shorter than the needle holds none of it, which is what the last
/// read of a mapping looks like.
#[test]
fn test_within_counts_nothing_in_less_than_a_needle() {
    assert_eq!(within(b"a", b"ab", false), 0);
}
