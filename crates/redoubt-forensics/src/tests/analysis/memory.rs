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
    Subject, analyse, answer, elsewhere, finalize_analyse, finalize_mappings, forked_analyse,
    frozen_measure, hex, inside, instrument, mappings, measure, named, next_skip, piped_analyse,
    recv, region, send, stand_still, sweep, traced_stand_still, within,
};
use crate::analysis::state::{BLOCK, ForensicState, MAGIC, OK, SHIPPED, STACK, Spans};
use crate::errors::{AnyError, DONE, Reason};

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
// Subject::freeze
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

    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

    let mut into = [0_u8; 8];

    assert_eq!(subject.read_at(at, &mut into), 8);
    assert_eq!(into, held);

    Ok(())
}

/// The photograph is a second process, not this one dressed up.
///
/// The whole of what the third process buys is that the memory being read is
/// not the memory doing the reading. A photograph of this process would be a
/// reading of a thing that moves while it is read, and it would arrive as a
/// number nobody could tell from the still one.
#[test]
fn test_photograph_is_of_a_child_and_not_of_us() -> Result<(), AnyError> {
    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

    // SAFETY: takes no argument and cannot fail.
    let mine = unsafe { libc::getpid() };

    assert_ne!(subject.of(), mine, "the photograph is of this process");

    Ok(())
}

// ============================================================================
// Subject::forked_freeze
// ============================================================================

/// Nothing where the fork did not happen.
///
/// The one branch of this that is not about a process, because there is no
/// process: `fork` answers `-1` when the system is out of what a process is
/// made of. What must not follow is a wait on a pid that is not one.
#[test]
fn test_forked_freeze_returns_nothing_where_there_was_no_fork() {
    assert!(Subject::forked_freeze(-1).is_none());
}

// ============================================================================
// Subject::forked_freeze_with
// ============================================================================

/// Nothing for a pid this process has no child by.
///
/// `waitpid` answers `ECHILD` there, and what must not happen is that the
/// refusal is read as a stop and the open below asked about somebody else's
/// process.
#[test]
fn test_forked_freeze_with_returns_nothing_for_a_pid_that_is_not_our_child() {
    // SAFETY: takes no argument and cannot fail.
    let mine = unsafe { libc::getpid() };

    assert!(Subject::forked_freeze_with(mine).is_none());
}

// ============================================================================
// Subject::finalize_freeze
// ============================================================================

/// Nothing for a child that left instead of stopping.
///
/// That is what a child says when the trace was refused: `PTRACE_TRACEME`
/// failed and it exited rather than stop, because a stop nobody is tracing is
/// never reported and the wait for it never ends.
#[test]
fn test_finalize_freeze_returns_nothing_for_a_child_that_did_not_stop() {
    // SAFETY: takes no argument and cannot fail.
    let mine = unsafe { libc::getpid() };

    assert!(Subject::finalize_freeze(mine, 0).is_none());
}

/// Nothing where the memory cannot be opened.
///
/// A pid nothing is running under has no `/proc/<pid>/mem` to open. The
/// alternative to answering `None` is a `Subject` holding `-1` as a
/// descriptor, whose every read comes back empty — a photograph of nothing,
/// indistinguishable from a process that holds nothing.
#[test]
fn test_finalize_freeze_returns_nothing_when_the_memory_cannot_be_opened() {
    // A stopped status for a pid that is not there. `0x7f` in the low byte is
    // what `WIFSTOPPED` reads, so this is the shape of a stop without one.
    assert!(Subject::finalize_freeze(libc::pid_t::MAX, 0x7f).is_none());
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
    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

    let mut into = [0xAA_u8; 8];

    assert_eq!(subject.read_at(1 << 47, &mut into), 0);
    assert_eq!(into, [0xAA; 8], "nothing was read, so nothing was written");

    Ok(())
}

// ============================================================================
// Subject::of
// ============================================================================

#[test]
#[ignore = "Covered transitively: the freeze section asserts that the pid this \
            answers is not this process's own, which is the only claim it \
            makes. Shell preserved in case it grows one."]
fn test_of_returns_the_pid_of_the_photograph() {
    // Intentionally empty.
}

// ============================================================================
// stand_still
// ============================================================================

/// The child stops, and its memory can be read by the one that forked it.
///
/// Asserted from outside, because there is no inside: the process that runs
/// this never returns from it. What the parent can see is the whole contract —
/// that it stopped, and that reading it is allowed, which is what the trace
/// was asked for and is granted to a tracer alone.
#[test]
fn test_stand_still_stops_the_child_where_its_parent_can_read_it() -> Result<(), AnyError> {
    let held: [u8; 8] = [0x3D, 0xA7, 0x14, 0xF2, 0x8B, 0x50, 0xC6, 0x29];
    let at = core::hint::black_box(&held).as_ptr() as u64;

    // SAFETY: `fork` with nothing of this library's in flight, and a child
    // that leaves without returning to Rust.
    let pid = unsafe { libc::fork() };

    assert!(pid >= 0, "no fork");

    if pid == 0 {
        stand_still();
    }

    let mut status = 0;

    // SAFETY: the pid is this process's own child, and the status is a local
    // this call writes into.
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };

    assert!(waited >= 0, "the child could not be waited on");
    assert!(
        libc::WIFSTOPPED(status),
        "the child left instead of stopping"
    );

    let mut path = [0_u8; 32];

    named(pid, b"/mem\0", &mut path);

    // SAFETY: the path is a buffer just written and terminated.
    let mem = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY) };

    assert!(mem >= 0, "the child stopped but is not ours to read");

    let mut into = [0_u8; 8];

    // SAFETY: a descriptor this test opened, and a live writable slice.
    let got =
        unsafe { libc::pread64(mem, into.as_mut_ptr().cast(), into.len(), at as libc::off_t) };

    // SAFETY: a descriptor this test opened, and its own stopped child.
    unsafe {
        libc::close(mem);
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, core::ptr::null_mut(), 0);
    }

    assert_eq!(got, 8, "the trace was not what let us read it");
    assert_eq!(into, held, "what came back is not what the child held");

    Ok(())
}

// ============================================================================
// traced_stand_still
// ============================================================================

/// A trace the machine refused is a child that leaves, and says so by leaving.
///
/// The one word it has: an exit of one. Staying instead would be a stop nobody
/// is tracing, which is never reported — the parent would wait for it until
/// somebody killed one of them.
#[test]
fn test_traced_stand_still_leaves_with_a_word_where_the_trace_was_refused() -> Result<(), AnyError>
{
    // SAFETY: `fork` with nothing of this library's in flight, and a child
    // that leaves without returning to Rust.
    let pid = unsafe { libc::fork() };

    assert!(pid >= 0, "no fork");

    if pid == 0 {
        traced_stand_still(-1);
    }

    let mut status = 0;

    // SAFETY: the pid is this process's own child, and the status is a local
    // this call writes into.
    unsafe { libc::waitpid(pid, &mut status, 0) };

    assert!(libc::WIFEXITED(status), "it stopped instead of leaving");
    assert_eq!(libc::WEXITSTATUS(status), 1, "it left without the word");

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
    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;
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

/// A line with no dash names no range, and the search for one says so.
#[test]
fn test_region_returns_nothing_for_a_line_with_no_dash() {
    assert_eq!(region(b""), None);
}

/// A line with no space ends before the flags, which is where the answer is.
#[test]
fn test_region_returns_nothing_for_a_line_with_no_space() {
    assert_eq!(region(b"7f8e1c000000-7f8e1c021000"), None);
}

/// Nothing where the dash comes after the space.
///
/// The two are found independently, so a line holding them in that order would
/// otherwise be read as a mapping running from one address to another that is
/// not past it: `hex` would be handed a stretch spanning the space, and what
/// came back would be a bound nobody wrote.
#[test]
fn test_region_returns_nothing_for_a_dash_that_is_past_the_space() {
    assert_eq!(region(b"7f8e1c000000 rw-p 00000000 00:00 0"), None);
}

/// A line that ends at the space has no flags to read, and asking for them off
/// the end is the refusal rather than two bytes of whatever follows.
#[test]
fn test_region_returns_nothing_for_a_line_that_ends_at_the_space() {
    assert_eq!(region(b"7f8e1c000000-7f8e1c021000 "), None);
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

/// A page open for writing alone, which is what a guarded page looks like
/// from outside while it is being read through. Skipped for the same reason.
#[test]
fn test_region_returns_nothing_for_a_write_only_page() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 -w-p 00000000 00:00 0"),
        None
    );
}

/// A first bound that is not a number is no bound, and reading it says so.
///
/// The first refusal that comes from what the line holds rather than from its
/// shape: everything up to here can be told from the punctuation alone.
#[test]
fn test_region_propagates_a_first_bound_that_is_not_hexadecimal() {
    assert_eq!(
        region(b"zzzzzzzzzzzz-7f8e1c021000 rw-p 00000000 00:00 0"),
        None,
    );
}

/// The second bound, read only once the first came back a number.
#[test]
fn test_region_propagates_a_second_bound_that_is_not_hexadecimal() {
    assert_eq!(
        region(b"7f8e1c000000-zzzzzzzzzzzz rw-p 00000000 00:00 0"),
        None,
    );
}

/// The bounds of a mapping that can be written to. Writable and not merely
/// readable, because what is left behind is left behind by writing.
#[test]
fn test_region_returns_the_bounds_of_a_writable_mapping() {
    assert_eq!(
        region(b"7f8e1c000000-7f8e1c021000 rw-p 00000000 00:00 0"),
        Some((0x7f8e_1c00_0000, 0x7f8e_1c02_1000)),
    );
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

/// Too many for the room there is, rather than as many as fit.
///
/// The run is where a sweep learns what to read, so one that stopped at the
/// room it had would have the analysis answer about part of a process while
/// reporting on all of it. Every process has more than one writable mapping,
/// so room for one is enough to ask.
#[test]
fn test_mappings_reports_too_many_mappings_when_there_is_no_room_for_them() {
    let mut text = vec![0_u8; 1 << 16];
    let mut block = vec![0_u64; 1 + 2];
    let mut maps = Spans::over(&mut block);

    // SAFETY: takes no argument and cannot fail.
    let mine = unsafe { libc::getpid() };

    assert!(matches!(
        mappings(mine, &mut text, &mut maps),
        Err(Reason::TooManyMappings),
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

// ============================================================================
// finalize_mappings
// ============================================================================

/// A listing that names no writable mapping is none, and not an empty sweep.
///
/// Reachable here and nowhere else: every process that can be asked about has
/// a stack, and a stack is writable, so through the open above this branch has
/// no input. A caller handed an empty list would sweep nothing and report that
/// the process holds nothing, which is the same words as a clean answer.
#[test]
fn test_finalize_mappings_reports_no_mappings_where_none_are_writable() {
    let mut block = [0_u64; 1 + 2 * 8];
    let mut maps = Spans::over(&mut block);

    let text = b"7f8e1c000000-7f8e1c021000 r-xp 00000000 00:00 0\n\
                 7f8e1c021000-7f8e1c022000 ---p 00000000 00:00 0\n";

    assert!(matches!(
        finalize_mappings(text, &mut maps),
        Err(Reason::NoMappings),
    ));
}

/// A line that names more than there is room for says so.
#[test]
fn test_finalize_mappings_reports_too_many_for_a_listing_wider_than_the_room() {
    // A count and room for one span after it.
    let mut block = [0_u64; 3];
    let mut maps = Spans::over(&mut block);

    let text = b"7f8e1c000000-7f8e1c021000 rw-p 00000000 00:00 0\n\
                 7f8e1c021000-7f8e1c022000 rw-p 00000000 00:00 0\n";

    assert!(matches!(
        finalize_mappings(text, &mut maps),
        Err(Reason::TooManyMappings),
    ));
}

/// The writable ones, and only those.
#[test]
fn test_finalize_mappings_returns_the_writable_mappings_alone() -> Result<(), AnyError> {
    let mut block = [0_u64; 1 + 2 * 8];
    let mut maps = Spans::over(&mut block);

    let text = b"7f8e1c000000-7f8e1c021000 rw-p 00000000 00:00 0\n\
                 7f8e1c021000-7f8e1c022000 r-xp 00000000 00:00 0\n\
                 7f8e1c022000-7f8e1c023000 rw-p 00000000 00:00 0\n";

    finalize_mappings(text, &mut maps)?;

    assert_eq!(
        maps.iter().collect::<Vec<_>>(),
        [
            (0x7f8e_1c00_0000, 0x7f8e_1c02_1000),
            (0x7f8e_1c02_2000, 0x7f8e_1c02_3000),
        ],
    );

    Ok(())
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

    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

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

/// It says so rather than quietly marking fewer than it found.
///
/// A sweep that ran out of room to skip would read the instrument's own block
/// as somebody's memory and find the secret in the one place it is certain to
/// be. Being told is the only safe answer.
#[test]
fn test_instrument_reports_too_many_blocks_when_there_is_no_room_to_mark_one()
-> Result<(), AnyError> {
    let held = MAGIC;
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

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

/// A stretch that holds no phrase is marked as nothing.
///
/// The tests above hand it a window that is the phrase and nothing else, so
/// every comparison in them matches. What a real sweep is almost entirely made
/// of is the other answer, and a run that marked those as blocks would have
/// the analysis step over somebody's memory.
#[test]
fn test_instrument_marks_nothing_in_a_stretch_without_the_phrase() -> Result<(), AnyError> {
    let held = [0x5A_u8; 64];
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

    let mut block = [0_u64; 3];
    let maps = skipping(&mut block, &[(at, at + 64)]);

    let mut room = [0_u64; 3];
    let mut skips = Spans::over(&mut room);

    let mut into = [0_u8; 4096];

    instrument(&subject, &mut into, &maps, &mut skips)?;

    assert!(skips.is_empty(), "it marked a block where there is none");

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

    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

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

    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

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

/// A mapping that cannot be read is a break and not an end.
///
/// The list of mappings is read before the photograph and a mapping can be
/// gone by the time the sweep reaches it, or be one the kernel will not hand
/// over. Nothing is counted there, and the caller is told, because a run it
/// was carrying must not walk across the hole as though the bytes were its
/// own.
#[test]
fn test_sweep_says_the_ground_broke_where_nothing_could_be_read() -> Result<(), AnyError> {
    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

    let mut block = [0_u64; 3];
    let maps = skipping(&mut block, &[(1 << 47, (1 << 47) + 4096)]);

    let mut empty = [0_u64; 3];
    let skips = skipping(&mut empty, &[]);

    let mut seen = Vec::new();
    let mut broke = false;
    let mut into = [0_u8; 4096];

    let swept = sweep(
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

    assert!(seen.is_empty(), "something came back: {seen:02x?}");
    assert!(broke, "the caller was not told the ground broke");
    assert_eq!(swept, 0, "nothing was there to read");

    Ok(())
}

/// A window with no room in it leaves, rather than asking for nothing forever.
///
/// How much is read is the lesser of what is left and what the window holds,
/// so a window of nothing makes that nothing — and the address never moves.
#[test]
fn test_sweep_leaves_a_mapping_where_there_is_no_window_to_read_into() -> Result<(), AnyError> {
    let held: [u8; 8] = [0x6C, 0x93, 0x2A, 0xE7, 0x51, 0xB8, 0x0D, 0xF4];
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

    let mut block = [0_u64; 3];
    let maps = skipping(&mut block, &[(at, at + 8)]);

    let mut empty = [0_u64; 3];
    let skips = skipping(&mut empty, &[]);

    let mut seen = Vec::new();

    let swept = sweep(&subject, &mut [], &maps, &skips, 0, |window, _, _| {
        seen.extend_from_slice(window);
    });

    assert!(seen.is_empty(), "something came back: {seen:02x?}");
    assert_eq!(swept, 0, "nothing was read");

    Ok(())
}

/// A mapping wider than the window comes back in pieces that share their seam.
///
/// The turn that matters is the second one: the address moves by the window
/// less the seam, so the bytes on the join are read twice on purpose. A run
/// that moved by the whole window would miss every needle straddling it, which
/// is the one thing the seam exists to prevent.
#[test]
fn test_sweep_carries_the_seam_from_one_window_to_the_next() -> Result<(), AnyError> {
    let held = [0x5A_u8; 64];
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

    let mut block = [0_u64; 3];
    let maps = skipping(&mut block, &[(at, at + 64)]);

    let mut empty = [0_u64; 3];
    let skips = skipping(&mut empty, &[]);

    let mut at_each = Vec::new();
    let mut into = [0_u8; 16];

    sweep(&subject, &mut into, &maps, &skips, 4, |window, from, _| {
        if !window.is_empty() {
            at_each.push(from - at);
        }
    });

    assert_eq!(
        at_each,
        [0, 12, 24, 36, 48],
        "the windows did not overlap by the seam",
    );

    Ok(())
}

/// A seam as wide as the window stops, rather than reading the same bytes for
/// as long as anybody waits.
///
/// The seam is how much consecutive windows share, so one that is the whole
/// window leaves nothing new in the next read. A caller asking for that is
/// asking for something it cannot have, and what it gets is an end.
#[test]
fn test_sweep_leaves_a_mapping_where_the_seam_is_the_whole_window() -> Result<(), AnyError> {
    let held = [0x5A_u8; 64];
    let at = core::hint::black_box(&held).as_ptr() as u64;

    let subject = Subject::freeze().ok_or(Reason::NoPhotograph)?;

    let mut block = [0_u64; 3];
    let maps = skipping(&mut block, &[(at, at + 64)]);

    let mut empty = [0_u64; 3];
    let skips = skipping(&mut empty, &[]);

    let mut windows = 0;
    let mut into = [0_u8; 8];

    sweep(&subject, &mut into, &maps, &skips, 8, |window, _, _| {
        if !window.is_empty() {
            windows += 1;
        }
    });

    assert_eq!(windows, 1, "it read past the first window and kept going");

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

// ============================================================================
// piped_analyse
// ============================================================================

/// Nothing to say it down, so nothing is measured.
///
/// The pipe is opened before anybody forks, and it is the only way back: an
/// analyst with nowhere to answer would read a process's whole memory and take
/// the answer to the grave.
#[test]
fn test_piped_analyse_reports_no_pipe_where_there_is_none() {
    let mut state = ForensicState::default();

    assert!(matches!(
        piped_analyse(&mut state, went_well, -1, [0, 0]),
        Err(Reason::NoPipe),
    ));
}

// ============================================================================
// forked_analyse
// ============================================================================

/// Both ends of a pipe, for every test below that needs one.
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

/// Nothing where the fork did not happen, and both ends closed on the way out.
///
/// A refusal that left the pipe open would leak two descriptors per attempt,
/// and the process that does this most is a test runner.
#[test]
fn test_forked_analyse_reports_no_fork_where_there_was_none() {
    let mut state = ForensicState::default();
    let (reading, writing) = piped();

    assert!(matches!(
        forked_analyse(&mut state, went_well, -1, reading, writing),
        Err(Reason::NoFork),
    ));

    // SAFETY: both are descriptors, closed or not, and this asks rather than
    // uses. `EBADF` is the answer being looked for.
    let again = unsafe { libc::close(reading) };

    assert_eq!(again, -1, "the reading end was left open");
}

/// Zero is the analyst, and the analyst answers down the pipe and leaves.
///
/// Asked from a process this test forked itself, because that is the only way
/// to be the analyst and still be around to read what it said. What the parent
/// checks is the contract of the wire: the whole result arrives, and the word
/// the reader believes is in it.
#[test]
fn test_forked_analyse_hands_zero_to_the_analyst() -> Result<(), AnyError> {
    let mut state = ForensicState::default();
    let (reading, writing) = piped();

    // SAFETY: `fork` with nothing of this library's in flight, and a child
    // that leaves through the analyst without returning to Rust.
    let pid = unsafe { libc::fork() };

    assert!(pid >= 0, "no fork");

    if pid == 0 {
        forked_analyse(&mut state, went_well, 0, reading, writing)?;
    }

    // SAFETY: the end this side will not write to.
    unsafe { libc::close(writing) };

    let mut into = [0_u8; SHIPPED * 8];
    let heard = recv(reading, &mut into);

    // SAFETY: a descriptor this test opened, and its own child.
    unsafe {
        libc::close(reading);
        libc::waitpid(pid, core::ptr::null_mut(), 0);
    }

    assert!(heard, "the analyst said nothing");

    let word = u64::from_ne_bytes(
        into[OK * 8..OK * 8 + 8]
            .try_into()
            .expect("eight bytes of the result"),
    );

    assert_eq!(
        word, DONE,
        "the analyst answered, but not that it went well"
    );

    Ok(())
}

// ============================================================================
// finalize_analyse
// ============================================================================

#[test]
#[ignore = "Covered transitively: the analyse section reaches this branch with \
            the same trigger, an analyst that leaves without writing, and \
            asserts the same reason. Shell preserved in case the wait grows a \
            second way of saying nothing."]
fn test_finalize_analyse_reports_no_answer_when_the_analyst_says_nothing() {
    // Intentionally empty.
}

/// Both ends closed by the time the answer is handed back.
///
/// Neither close is visible in the result, and the process doing this most is a
/// test runner: two descriptors per photograph, against a limit nothing here
/// raises. The kernel is what says so — a second `close` of a descriptor this
/// already closed is `EBADF`, and of one it left open is success.
#[test]
fn test_finalize_analyse_closes_both_ends_of_the_pipe() -> Result<(), AnyError> {
    let mut state = ForensicState::default();
    let (reading, writing) = piped();

    // SAFETY: `fork` with nothing of this library's in flight, and a child that
    // leaves through the analyst without returning to Rust.
    let pid = unsafe { libc::fork() };

    assert!(pid >= 0, "no fork");

    if pid == 0 {
        answer(&mut state, went_well, reading, writing);
    }

    finalize_analyse(&mut state, pid, reading, writing)?;

    // SAFETY: both are descriptors, closed or not, and this asks rather than
    // uses. `EBADF` is the answer being looked for.
    let (again, once_more) = unsafe { (libc::close(reading), libc::close(writing)) };

    assert_eq!(again, -1, "the reading end was left open");
    assert_eq!(once_more, -1, "the writing end was left open");

    Ok(())
}

// ============================================================================
// answer
// ============================================================================

/// Work that measures nothing and writes nothing, so that what the parent reads
/// back is whatever was in the block before the analyst was asked.
fn wrote_nothing(_state: &mut ForensicState, _subject: &Subject) -> Result<(), Reason> {
    Ok(())
}

/// What the last photograph came to is gone before this one answers.
///
/// A stale number read as a fresh one is the same mistake as a refusal read as
/// a zero, and neither says anything on its way past: the block is the caller's
/// and it survives from one photograph to the next, so a word this did not
/// write is a word the last sweep wrote. The dirtying happens before the fork,
/// which is what makes the child inherit it.
#[test]
fn test_answer_clears_what_the_last_photograph_left() {
    let mut state = ForensicState::default();
    let (reading, writing) = piped();

    for word in 0..SHIPPED {
        state.parts().result[word] = 0x5C5C_5C5C_5C5C_5C5C;
    }

    // SAFETY: `fork` with nothing of this library's in flight, and a child that
    // leaves through the analyst without returning to Rust.
    let pid = unsafe { libc::fork() };

    assert!(pid >= 0, "no fork");

    if pid == 0 {
        answer(&mut state, wrote_nothing, reading, writing);
    }

    // SAFETY: the end this side will not write to.
    unsafe { libc::close(writing) };

    let mut into = [0_u8; SHIPPED * 8];
    let heard = recv(reading, &mut into);

    // SAFETY: a descriptor this test opened, and its own child.
    unsafe {
        libc::close(reading);
        libc::waitpid(pid, core::ptr::null_mut(), 0);
    }

    assert!(heard, "the analyst said nothing");

    for word in 0..SHIPPED {
        let read = u64::from_ne_bytes(
            into[word * 8..word * 8 + 8]
                .try_into()
                .expect("eight bytes of the result"),
        );

        let expected = if word == OK { DONE } else { 0 };

        assert_eq!(read, expected, "word {word} came back from the last sweep");
    }
}

// ============================================================================
// measure
// ============================================================================

/// Eight bytes at an address that is the same one every time, so that the work
/// below can name it without being handed anything.
static HELD: [u8; 8] = [0x3D, 0xA7, 0x14, 0xF2, 0x8B, 0x50, 0xC6, 0x29];

/// Work that reports what it was given: the mappings it can see, and nothing
/// at all if the photograph does not hold what this process holds.
fn what_it_was_handed(state: &mut ForensicState, subject: &Subject) -> Result<(), Reason> {
    let mut into = [0_u8; 8];
    let got = subject.read_at(core::ptr::addr_of!(HELD) as u64, &mut into);

    let parts = state.parts();
    let many = parts.maps.len() as u64;

    parts.result[SHIPPED - 1] = if got == 8 && into == HELD { many } else { 0 };

    Ok(())
}

/// The work is handed a photograph and the mappings of it, already read.
///
/// The one thing the analyst owes the work, and the one nothing asserted:
/// every sweep is over the list this filled, so a work handed an empty list
/// answers that the process is clean while having read none of it.
///
/// Called here rather than through [`analyse`], which is the point of it being
/// its own function: through the fork, what the work saw is only what fits in
/// the result, and what it did not see is indistinguishable from what it
/// found.
#[test]
fn test_measure_hands_the_work_a_photograph_and_its_mappings() -> Result<(), AnyError> {
    let mut state = ForensicState::default();

    measure(&mut state, what_it_was_handed)?;

    assert!(
        state.read(SHIPPED - 1) > 0,
        "the work was handed no mappings, or a photograph that is not of us",
    );

    Ok(())
}

// ============================================================================
// frozen_measure
// ============================================================================

/// No photograph is no measurement, and the work is never asked.
///
/// What a machine that refuses `ptrace` hands back. The alternative is a sweep
/// over no mappings, which comes back as a count of zero — the same number as
/// a process that holds nothing.
#[test]
fn test_frozen_measure_reports_no_photograph_where_there_is_none() {
    let mut state = ForensicState::default();

    assert!(matches!(
        frozen_measure(&mut state, went_badly, None),
        Err(Reason::NoPhotograph),
    ));
}

// ============================================================================
// send
// ============================================================================

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

/// `false` where there is nobody left to write to.
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

/// `false` for a pipe that ended before it had said everything.
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

// ============================================================================
// elsewhere
// ============================================================================

/// Work that answers where it was standing.
///
/// The last word of the result, which nothing else uses, so the parent reads
/// it back out of the pipe like any other number the analysis returns.
fn where_it_stood(state: &mut ForensicState, _subject: &Subject) -> Result<(), Reason> {
    let here = 0_u8;

    state.parts().result[SHIPPED - 1] = core::ptr::from_ref(&here) as u64;

    Ok(())
}

/// The work runs on the block's own stack, and not on the caller's.
///
/// Which is the whole of what this is for: every frame the instrument pushes
/// from here on lands in the one stretch a sweep steps over, so the hundred
/// bytes below the caller — where a spill of the secret would be — are never
/// written over before the photograph reads them.
///
/// Asked of the address a local of the work actually has, because the claim is
/// about where the machine put it and not about what the code asked for.
#[test]
fn test_elsewhere_runs_the_work_on_the_block_s_own_stack() -> Result<(), AnyError> {
    let mut state = ForensicState::default();
    let top = state.stack_top() as u64;

    elsewhere(&mut state, where_it_stood)?;

    let stood = state.read(SHIPPED - 1);

    assert!(
        stood <= top && top - stood < STACK as u64,
        "the work stood at {stood:#x}, which is not in the quarter megabyte \
         below {top:#x}",
    );

    Ok(())
}

/// A reason the work gave, carried back across the switch.
///
/// The errand cannot hand over a `Result` — it is written from a stack the
/// compiler knows nothing about — so it carries a code and this builds the
/// reason again on the way out.
#[test]
fn test_elsewhere_brings_back_the_reason_the_work_gave() {
    let mut state = ForensicState::default();

    assert!(matches!(
        elsewhere(&mut state, went_badly),
        Err(Reason::TooManyBlocks),
    ));
}
