// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The one block, and what is where in it.
//!
//! # Why the layout is worth asserting
//!
//! Every piece of the block is handed out as a slice built from a raw pointer
//! and a length, and what makes that sound is a paragraph: the offsets are
//! multiples of eight, the pieces lie end to end, none of them reaches past
//! what was reserved. All of it true when it was written, and none of it
//! checked by anything — one constant moved by one is a paragraph that has
//! quietly stopped describing the code it sits above, and the compiler has no
//! opinion about that.
//!
//! So the pieces are asked where they are, and held to not standing on each
//! other.

use crate::analysis::state::{
    BLOCK, COUNT, FOUND, ForensicState, MAGIC, MAPPINGS, MOST, OK, RUNS, SCORE, SHIPPED, SKIPS,
    SWEPT, Spans, WIDEST,
};

// ============================================================================
// Spans::len
// ============================================================================

/// One more for each one taken, and nothing for one refused.
#[test]
fn test_spans_len_counts_the_ones_it_took() {
    // A count, and room for two spans after it.
    let mut room = [0_u64; 5];
    let mut spans = Spans::over(&mut room);

    assert_eq!(spans.len(), 0);

    spans.push((100, 200));
    assert_eq!(spans.len(), 1);

    spans.push((300, 400));
    spans.push((500, 600));
    assert_eq!(spans.len(), 2, "the one it refused was counted anyway");
}

// ============================================================================
// Spans::is_empty
// ============================================================================

/// Empty until one is taken.
#[test]
fn test_spans_is_empty_until_one_is_taken() {
    let mut room = [0_u64; 9];
    let mut spans = Spans::over(&mut room);

    assert!(spans.is_empty());

    spans.push((100, 200));

    assert!(!spans.is_empty());
}

// ============================================================================
// Spans::clear
// ============================================================================

/// Back to none, which is what one block serving every photograph needs.
///
/// What the last one found has to go before the next one starts counting, or a
/// sweep steps over stretches that belonged to a photograph nobody is looking
/// at any more.
#[test]
fn test_spans_clear_takes_it_back_to_none() {
    let mut room = [0_u64; 9];
    let mut spans = Spans::over(&mut room);

    spans.push((100, 200));
    spans.clear();

    assert!(spans.is_empty());
    assert_eq!(spans.iter().count(), 0);

    assert!(spans.push((300, 400)), "and it takes them again");
    assert_eq!(spans.get(0), (300, 400));
}

// ============================================================================
// Spans::push
// ============================================================================

/// It says no rather than taking one it has nowhere to put.
///
/// A run that quietly stopped recording would have a sweep read the
/// instrument's own block as somebody's memory and find the secret in the one
/// place it is certain to be. Being told is the only answer that is not a lie.
#[test]
fn test_spans_push_refuses_one_more_than_it_has_room_for() {
    let mut room = [0_u64; 5];
    let mut spans = Spans::over(&mut room);

    assert!(spans.push((100, 200)));
    assert!(spans.push((300, 400)));
    assert!(!spans.push((500, 600)));

    assert_eq!(spans.get(1), (300, 400), "it overwrote the last one");
}

/// What it refuses, it leaves out of the words past the count.
///
/// The run lives in the block, and the words past the last span are the next
/// piece. One written there anyway is a refusal that did the write regardless.
#[test]
fn test_spans_push_that_refuses_writes_nothing() {
    let mut room = [0_u64; 5];

    {
        let mut spans = Spans::over(&mut room);

        spans.push((100, 200));
        spans.push((300, 400));
        spans.push((u64::MAX, u64::MAX));
    }

    assert_eq!(room, [2, 100, 200, 300, 400]);
}

/// Both halves of a span survive the trip, each a whole word.
///
/// They are addresses, and the high half of an address is the half that says
/// which mapping it is in. A pair truncated into one word is a sweep over
/// somewhere else entirely.
#[test]
fn test_spans_push_keeps_both_halves_of_every_span_whole() {
    let mut room = [0_u64; 9];
    let mut spans = Spans::over(&mut room);

    assert!(spans.push((u64::MAX, 0)));
    assert!(spans.push((0, u64::MAX)));

    assert_eq!(spans.get(0), (u64::MAX, 0));
    assert_eq!(spans.get(1), (0, u64::MAX));
}

// ============================================================================
// Spans::get
// ============================================================================

/// The one at that place, and not its neighbour.
///
/// The run is one stretch of words with no marks between the spans, so a read
/// off by a word is the end of one mapping paired with the start of the next —
/// a stretch of address space that was never anybody's.
#[test]
fn test_spans_get_returns_the_one_at_that_place() {
    let mut room = [0_u64; 9];
    let mut spans = Spans::over(&mut room);

    spans.push((100, 200));
    spans.push((300, 400));

    assert_eq!(spans.get(0), (100, 200));
    assert_eq!(spans.get(1), (300, 400));
}

// ============================================================================
// Spans::iter
// ============================================================================

/// All of them, in the order they were pushed, and none of the room past them.
#[test]
fn test_spans_iter_returns_all_of_them_in_the_order_they_went_in() {
    let mut room = [0_u64; 9];
    let mut spans = Spans::over(&mut room);

    spans.push((100, 200));
    spans.push((300, 400));

    assert_eq!(spans.iter().collect::<Vec<_>>(), [(100, 200), (300, 400)]);
}

// ============================================================================
// Spans::over
// ============================================================================

/// A run begins empty over words that were left holding something.
///
/// The words are the caller's scratch and a caller reuses it: the count lives
/// in the first of them, so a run that took what was there would start at
/// whatever the last photograph pushed and write its spans past the room.
#[test]
fn test_over_starts_a_run_that_is_empty_whatever_the_words_held() {
    let mut room = [u64::MAX; 9];

    assert!(Spans::over(&mut room).is_empty());
}

// ============================================================================
// Spans::at
// ============================================================================

/// The caller's own words, and their width in bytes rather than in words.
///
/// What reads this is the sweep, which skips by address and length: a width
/// eight times short would leave seven eighths of the run swept as though it
/// were somebody else's memory.
#[test]
fn test_at_returns_the_words_it_was_given_and_their_width_in_bytes() {
    let mut room = [0_u64; 9];
    let stood = room.as_ptr() as usize;

    assert_eq!(Spans::over(&mut room).at(), (stood, 72));
}

// ============================================================================
// ForensicState::whole
// ============================================================================

#[test]
#[ignore = "Covered transitively: the default section reads the block through \
            this, asserting it is BLOCK bytes long and begins at the phrase, \
            which is the whole of what it hands back. Shell preserved in case \
            it grows a second caller."]
fn test_whole_returns_the_block_from_the_phrase_at_its_front() {}

// ============================================================================
// ForensicState::default
// ============================================================================

/// The phrase is at the front, which is the whole protocol for finding one.
///
/// A sweep looks for exactly these bytes and skips [`BLOCK`] from each. A block
/// that did not begin with them would be memory the instrument keeps between
/// one photograph and the next, counted as if it were somebody else's — and
/// what it keeps is the needle.
#[test]
fn test_default_writes_the_phrase_at_the_front() {
    let mut state = ForensicState::default();

    assert_eq!(&state.whole()[..MAGIC.len()], &MAGIC[..]);
}

/// Nothing else is written at all.
///
/// The child may not allocate, so everything it will ever touch is reserved
/// here — and a reading left over from the last measurement is indeterminable
/// from one this measurement made.
#[test]
fn test_default_leaves_everything_past_the_phrase_empty() {
    let mut state = ForensicState::default();
    let block = state.whole();

    assert_eq!(block.len(), BLOCK);
    assert!(block[MAGIC.len()..].iter().all(|byte| *byte == 0));
}

// ============================================================================
// ForensicState::hold
// ============================================================================

/// A needle of nothing is not a needle.
///
/// Every byte of memory holds it, so a sweep for it answers that the secret is
/// everywhere — which is the same as answering nothing, said loudly.
#[test]
fn test_hold_refuses_a_needle_of_nothing() {
    let mut state = ForensicState::default();

    assert!(!state.hold(&[], false));
}

/// A needle wider than the room set aside for it.
///
/// The room cannot grow: it is a piece of a block reserved before the
/// photograph, which is the entire reason it is reserved. A needle that did not
/// fit and was taken anyway would be written over whatever the next piece is.
#[test]
fn test_hold_refuses_a_needle_wider_than_the_room_for_it() {
    let mut state = ForensicState::default();

    assert!(!state.hold(&[0x5A; MOST + 1], false));
}

/// The narrowest there can be is taken, and the widest there is room for.
#[test]
fn test_hold_takes_a_needle_from_one_byte_to_the_whole_room() {
    let mut state = ForensicState::default();

    assert!(state.hold(&[0x5A], false));
    assert_eq!(state.of, 1);

    assert!(state.hold(&[0x5A; MOST], false));
    assert_eq!(state.of, MOST);
}

/// What went in is what is held, byte for byte, and nothing past it.
#[test]
fn test_hold_keeps_the_needle_it_was_given_and_writes_no_further() {
    let needle = [0x6C_u8, 0x93, 0x2A, 0xE7, 0x51, 0xB8, 0x0D, 0xF4];
    let mut state = ForensicState::default();

    assert!(state.hold(&needle, false));

    let secret = state.parts().secret;

    assert_eq!(&secret[..needle.len()], &needle[..]);
    assert!(secret[needle.len()..].iter().all(|byte| *byte == 0));
}

/// Which way round the child reads it is the caller's to say.
///
/// A needle arrives backwards because writing it forwards here would be a copy
/// of the secret in the process that is looking for copies of the secret. Which
/// of the two it is cannot be guessed from the bytes.
#[test]
fn test_hold_keeps_which_way_round_the_needle_is() {
    let mut state = ForensicState::default();

    assert!(state.hold(&[0x5A], true));
    assert!(state.backwards);

    assert!(state.hold(&[0x5A], false));
    assert!(!state.backwards, "the last word is the caller's latest");
}

/// A refused needle leaves the last good one where it was.
///
/// `hold` writes three things and returns before any of them on the way out, so
/// a caller that ignores the answer sweeps for what it last asked for rather
/// than for half of something.
#[test]
fn test_hold_that_refuses_leaves_the_last_needle_alone() {
    let mut state = ForensicState::default();

    assert!(state.hold(&[0x11, 0x22, 0x33], true));
    assert!(!state.hold(&[0x5A; MOST + 1], false));

    assert_eq!(state.of, 3);
    assert!(state.backwards);
    assert_eq!(&state.parts().secret[..3], &[0x11, 0x22, 0x33]);
}

// ============================================================================
// ForensicState::shipped
// ============================================================================

/// What the pipe carries is the result, and the whole of it.
///
/// One side writes counters and the other reads bytes. If the two named
/// different stretches of the block, every photograph would come back as zeros
/// — which is also what "the secret is nowhere" looks like.
#[test]
fn test_shipped_is_the_bytes_of_the_result_the_analysis_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut state = ForensicState::default();

    state.parts().result[FOUND] = 1;
    state.parts().result[COUNT] = 0x0102_0304_0506_0708;

    let shipped = state.shipped();

    assert_eq!(shipped.len(), SHIPPED * 8);
    assert_eq!(shipped[0], 1, "the first counter is at the front");
    assert_eq!(
        u64::from_ne_bytes(shipped[COUNT * 8..COUNT * 8 + 8].try_into()?,),
        0x0102_0304_0506_0708,
    );

    Ok(())
}

// ============================================================================
// ForensicState::parts
// ============================================================================

/// Every table is as long as what it has one entry per.
///
/// Not the constant it was reserved with, which would be the constant asserting
/// itself. `next` is a bit for every ordered pair of byte values, `seen` a bit
/// for every byte value, and the three that walk beside the needle are as long
/// as the needle. A table short by one entry is a sweep reading a bit that
/// belongs to the next piece as if it were its own — and every entry past the
/// last one it can reach is a stretch of the secret it will never recognise.
#[test]
fn test_parts_hands_out_tables_with_one_entry_for_what_they_index() {
    let mut state = ForensicState::default();
    let parts = state.parts();
    let needle = parts.secret.len();

    assert_eq!(parts.next.len() * 8, 256 * 256, "a bit per ordered pair");
    assert_eq!(parts.seen.len() * 8, 256, "a bit per byte value");
    assert_eq!(
        parts.widths.len(),
        needle,
        "a counter per width a run can be"
    );
    assert_eq!(parts.lens.len(), needle, "a counter per byte of the needle");
    assert_eq!(parts.tail.len(), needle, "as far back as a run can be read");
    assert_eq!(parts.result.len(), SHIPPED, "what the pipe carries");
}

/// No two pieces of the block stand on each other, and none reaches past it.
///
/// The claim the `SAFETY` paragraph above `parts` makes, asked of the addresses
/// rather than read off the constants that were used to write it. Two pieces
/// overlapping is one of them writing over the other — the needle into the
/// window, a counter into the stack the analysis runs on — and nothing else in
/// this crate would notice.
#[test]
fn test_parts_hands_out_pieces_that_do_not_stand_on_each_other() {
    let mut state = ForensicState::default();
    let front = state.whole().as_ptr() as usize;

    let mut pieces: Vec<(&str, usize, usize)> = Vec::new();

    {
        let parts = state.parts();

        pieces.push(("held", parts.held.as_ptr() as usize, parts.held.len()));
        pieces.push(("report", parts.report.as_ptr() as usize, parts.report.len()));
        pieces.push(("secret", parts.secret.as_ptr() as usize, parts.secret.len()));
        pieces.push(("next", parts.next.as_ptr() as usize, parts.next.len()));
        pieces.push(("seen", parts.seen.as_ptr() as usize, parts.seen.len()));
        pieces.push((
            "widths",
            parts.widths.as_ptr() as usize,
            parts.widths.len() * 8,
        ));
        pieces.push(("tail", parts.tail.as_ptr() as usize, parts.tail.len()));
        pieces.push(("lens", parts.lens.as_ptr() as usize, parts.lens.len() * 2));
        pieces.push((
            "result",
            parts.result.as_ptr() as usize,
            parts.result.len() * 8,
        ));

        let (at, of) = parts.skips.at();
        pieces.push(("skips", at, of));

        let (at, of) = parts.maps.at();
        pieces.push(("maps", at, of));
    }

    pieces.sort_by_key(|(_, at, _)| *at);

    let (first, at, _) = pieces[0];

    assert!(at >= front + MAGIC.len(), "{first} stands on the phrase");

    for pair in pieces.windows(2) {
        let (name, at, of) = pair[0];
        let (next_name, next_at, _) = pair[1];

        assert!(
            at + of <= next_at,
            "{name} runs to {} and {next_name} begins at {next_at}",
            at + of,
        );
    }

    let (last, at, of) = pieces[pieces.len() - 1];

    assert!(
        at + of <= front + BLOCK,
        "{last} runs {} bytes past the end of the block",
        (at + of) - (front + BLOCK),
    );
}

/// Every one of them is eight-aligned, which is what makes the `u64` views
/// of them sound.
///
/// A `u64` read from an address that is not a multiple of eight is undefined
/// behaviour that happens to work on both architectures this runs on, which is
/// the worst kind: nothing fails until a compiler decides to use the alignment
/// it was promised.
#[test]
fn test_parts_hands_out_pieces_that_are_all_eight_aligned() {
    let mut state = ForensicState::default();
    let parts = state.parts();

    for (name, at) in [
        ("held", parts.held.as_ptr() as usize),
        ("report", parts.report.as_ptr() as usize),
        ("secret", parts.secret.as_ptr() as usize),
        ("next", parts.next.as_ptr() as usize),
        ("seen", parts.seen.as_ptr() as usize),
        ("widths", parts.widths.as_ptr() as usize),
        ("tail", parts.tail.as_ptr() as usize),
        ("lens", parts.lens.as_ptr() as usize),
        ("result", parts.result.as_ptr() as usize),
        ("skips", parts.skips.at().0),
        ("maps", parts.maps.at().0),
    ] {
        assert_eq!(at % 8, 0, "{name} is not eight-aligned");
    }
}

/// The two runs of spans hold as many as they were promised, and no fewer.
///
/// `SKIPS` is how many stretches of its own memory one sweep can step over, and
/// running out is the case that reads the instrument as somebody else's memory.
/// The number that matters is the one the run will actually take, not the one
/// written beside it.
#[test]
fn test_parts_hands_out_runs_that_take_as_many_spans_as_promised() {
    let mut state = ForensicState::default();
    let mut parts = state.parts();

    for one in 0..SKIPS {
        assert!(parts.skips.push((one as u64, one as u64)), "skip {one}");
    }

    assert!(!parts.skips.push((0, 0)), "it took more than {SKIPS}");

    for one in 0..MAPPINGS {
        assert!(parts.maps.push((one as u64, one as u64)), "mapping {one}");
    }

    assert!(!parts.maps.push((0, 0)), "it took more than {MAPPINGS}");
}

// ============================================================================
// ForensicState::stack_top
// ============================================================================

/// Sixteen-aligned, which the machine requires and nothing else checks.
///
/// It is written straight into the stack pointer. On `aarch64` a stack pointer
/// that is not a multiple of sixteen faults on the first thing the callee
/// stores, and the fault arrives as a signal rather than as an error anybody
/// can read.
#[test]
fn test_stack_top_is_aligned_as_a_stack_pointer_must_be() {
    let mut state = ForensicState::default();

    assert_eq!(state.stack_top() as usize % 16, 0);
}

/// It is the far end of a piece of the block, not of somebody's memory.
///
/// The analysis runs on it, so every frame it pushes lands in the one stretch a
/// sweep steps over. A stack outside the block is the instrument writing its
/// own working into what it is measuring.
#[test]
fn test_stack_top_is_inside_the_block_it_was_reserved_in() {
    let mut state = ForensicState::default();

    let top = state.stack_top() as usize;
    let front = state.whole().as_ptr() as usize;

    assert!(
        top > front,
        "the stack grows down, so it starts past the front"
    );
    assert!(
        top <= front + BLOCK,
        "the stack begins {} bytes past the end of the block",
        top - (front + BLOCK),
    );
}

/// There is room under it for everything the analysis will push.
///
/// A stack that overflows here does not grow a page: it runs down into the
/// pieces below it, which are the counters the analysis is filling and the
/// needle it is looking for.
#[test]
fn test_stack_top_has_the_whole_stack_under_it() {
    let mut state = ForensicState::default();

    let top = state.stack_top() as usize;
    let highest = {
        let parts = state.parts();
        let (at, of) = parts.maps.at();

        at + of
    };

    assert!(
        top - highest >= 1 << 18,
        "only {} bytes of stack under the top",
        top - highest,
    );
}

// ============================================================================
// ForensicState::read
// ============================================================================

/// Nothing, before anything has been measured.
///
/// Zero is what "the secret is nowhere" looks like, so a reading left behind by
/// the last measurement is one nobody can tell from a clean photograph.
#[test]
fn test_read_returns_nothing_before_anything_has_been_measured() {
    let mut state = ForensicState::default();

    for (at, name) in [
        (FOUND, "found"),
        (SCORE, "score"),
        (SWEPT, "swept"),
        (WIDEST, "widest"),
        (RUNS, "runs"),
        (OK, "ok"),
        (COUNT, "count"),
    ] {
        assert_eq!(state.read(at), 0, "{name} was not reserved empty");
    }
}

/// Each name is a different number, read back as what was written to it.
///
/// They are offsets into one run, so two that landed on the same word would be
/// a score reported as a count — with nothing anywhere to say so.
#[test]
fn test_read_gives_each_name_back_its_own_number() {
    let mut state = ForensicState::default();

    let every = [
        (FOUND, "found"),
        (SCORE, "score"),
        (SWEPT, "swept"),
        (WIDEST, "widest"),
        (RUNS, "runs"),
        (OK, "ok"),
        (COUNT, "count"),
    ];

    for (one, (at, _)) in every.iter().enumerate() {
        state.parts().result[*at] = one as u64 + 1;
    }

    for (one, (at, name)) in every.iter().enumerate() {
        assert_eq!(state.read(*at), one as u64 + 1, "{name} is somebody else");
    }
}

// ============================================================================
// ForensicState::drop
// ============================================================================

#[test]
#[ignore = "Uncovered: the only witness to what this wipes is a read of the \
            chunk the same drop hands back to the allocator, which is \
            undefined behaviour in a test — by then the chunk may be \
            somebody else's. Shell preserved in case the wipe grows something \
            observable before the free."]
fn test_drop_leaves_no_phrase_behind_in_the_heap() {}
