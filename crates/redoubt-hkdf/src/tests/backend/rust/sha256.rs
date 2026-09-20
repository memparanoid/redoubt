// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a `Sha256State` leaves behind, and the buffer the seam never reaches.
//!
//! `sha256_hash` takes a whole message, so no caller of this crate reaches
//! `update` — and `update` is the only thing that carries part of a block from
//! one call to the next. A caller that has its message in pieces is the kind
//! this crate has not got yet, and the branch is measured here rather than left
//! uncovered.
//!
//! What it is held to is this implementation answering the same for a message
//! it was given whole. NIST publishes the digest and not the buffering, so the
//! published answers cannot reach it.

use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::backend::rust::sha256::Sha256State;
use crate::consts::HASH_SIZE;

// ============================================================================
// Sha256State: zeroization
// ============================================================================

/// Emptying a state that is holding something empties it.
///
/// The dirtying is the half that makes the answer worth anything: a probe that
/// reached nowhere would report a clean state, and so would a clean one.
#[test]
fn test_sha256_state_is_zeroizable() {
    let mut state = Sha256State::new();

    state.unzeroize();
    assert!(!state.is_zeroized());

    state.fast_zeroize();
    assert!(state.is_zeroized());
}

/// A state that goes out of scope holding something empties itself.
#[test]
fn test_sha256_state_zeroizes_on_drop() {
    let mut state = Sha256State::new();

    state.unzeroize();
    assert!(!state.is_zeroized());

    state.assert_zeroize_on_drop();
}

// ============================================================================
// Sha256State::update
// ============================================================================

/// A message handed over in two pieces, cut where a block does not end.
///
/// Thirty bytes then twenty-six: the cut leaves the buffer part full, which is
/// the state `update` exists to carry and the one a caller with a whole message
/// never puts it in.
#[test]
fn test_update_answers_the_same_for_a_message_cut_inside_a_block() {
    let first = b"abcdbcdecdefdefgefghfghighijhijk";
    let second = b"ijkljklmklmnlmnomnopnopq";

    let mut piecemeal = [0_u8; HASH_SIZE];
    let mut state = Sha256State::new();

    state.update(first);
    state.update(second);
    state.finalize(&mut piecemeal);

    let mut whole = [0_u8; HASH_SIZE];
    let mut once = Sha256State::new();

    once.hash(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        &mut whole,
    );

    assert_eq!(piecemeal, whole);
}

/// A message handed over in pieces that are not a factor of the block.
///
/// Fifteen bytes at a time over a hundred and twelve: the buffer fills, empties
/// and part-fills again with a different remainder each turn, so a carry that
/// works for one alignment and not another has somewhere to show.
#[test]
fn test_update_answers_the_same_for_a_message_cut_at_every_alignment() {
    let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    let mut piecemeal = [0_u8; HASH_SIZE];
    let mut state = Sha256State::new();

    for piece in message.chunks(15) {
        state.update(piece);
    }

    state.finalize(&mut piecemeal);

    let mut whole = [0_u8; HASH_SIZE];
    let mut once = Sha256State::new();

    once.hash(message, &mut whole);

    assert_eq!(piecemeal, whole);
}
