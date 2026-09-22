// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each entry point answers, asked of every backend the target has.

use std::vec::Vec;

use proptest::prelude::*;
use rstest::rstest;

use redoubt_aead_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};
use redoubt_asm::Backend;
use redoubt_zero::ZeroizationProbe;

use crate::poly1305::tag_with_backend;

use crate::tests::support::oracle;
use crate::tests::support::{keyed, tag_of, tag_of_split};

// === === === === === === === === === ===
// update
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_update_returns_the_same_tag_at_every_split(#[case] backend: Backend) {
    let key = [0x5e; KEY_SIZE];
    let message: Vec<u8> = (0..70u16).map(|i| i as u8).collect();
    let whole = tag_of(backend, &key, &message);

    for at in 0..=message.len() {
        assert_eq!(
            tag_of_split(backend, &key, &message, at),
            whole,
            "split at {at} of {}",
            message.len()
        );
    }
}

proptest! {
    /// The same message in any number of pieces, against the oracle.
    ///
    /// The one above compares this path against itself: every split agrees, and
    /// they would still all agree if the buffer dropped the same byte in every
    /// one of them. And the oracle proptest below enters through
    /// `tag_with_backend`, which hands the whole message over at once and never
    /// carries `filled` across a call.
    ///
    /// This is the only thing that holds a partial buffer to an answer computed
    /// another way: a random key, a random message, and cuts wherever they
    /// fall — so a block boundary, a one-byte tail and several whole blocks in
    /// a row all arrive without being asked for.
    #[test]
    fn test_update_returns_what_the_oracle_returns_at_every_partition(
        key: [u8; KEY_SIZE],
        message in proptest::collection::vec(any::<u8>(), 0..600),
        cuts in proptest::collection::vec(any::<usize>(), 0..8),
    ) {
        let expected = oracle::tag(&key, &message);

        // Anywhere in the message, in order, and no offset twice.
        let mut offsets: Vec<usize> =
            cuts.iter().map(|cut| cut % (message.len() + 1)).collect();
        offsets.sort_unstable();
        offsets.dedup();

        for backend in [Backend::Rust, Backend::Auto] {
            let mut poly = keyed(backend, &key);
            let mut tag = [0u8; TAG_SIZE];
            let mut from = 0;

            for &to in &offsets {
                poly.update(&message[from..to]);
                from = to;
            }

            poly.update(&message[from..]);
            poly.finalize_mut(&mut tag);

            prop_assert_eq!(tag, expected, "{:?}, cut at {:?}", backend, offsets);
        }
    }
}

// === === === === === === === === === ===
// update_padded
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_update_padded_returns_the_tag_of_the_message_and_its_zeros(#[case] backend: Backend) {
    let key = [0x91; KEY_SIZE];

    // Nothing owed at 0, 16 and 32; fifteen owed at 1 and 17; one owed at 15
    // and 31. The multiples are what a `% BLOCK_SIZE` written once instead of
    // twice gets wrong, by owing a whole block of zeros that nobody owes.
    for length in [0usize, 1, 15, 16, 17, 31, 32] {
        let message: Vec<u8> = (0..length).map(|i| (i as u8) ^ 0x5a).collect();

        let mut padded = message.clone();
        padded.resize(length.next_multiple_of(BLOCK_SIZE), 0);

        let mut poly = keyed(backend, &key);
        let mut tag = [0u8; TAG_SIZE];

        poly.update_padded(&message);
        poly.finalize_mut(&mut tag);

        assert_eq!(tag, tag_of(backend, &key, &padded), "{length} bytes in");
    }
}

// === === === === === === === === === ===
// finalize_mut
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_finalize_mut_empties_the_state_it_answered_from(#[case] backend: Backend) {
    // Long enough to leave a tail in the buffer: what an emptying that only
    // reached the accumulator would leave behind is the last block of the
    // message, and a message ending on a boundary would not have one.
    let key = [0x3f; KEY_SIZE];
    let message = b"long enough to leave a tail in the buffer at the end";

    let mut poly = keyed(backend, &key);
    let mut tag = [0u8; TAG_SIZE];

    poly.update(message);
    poly.finalize_mut(&mut tag);

    // Assert zeroization!
    assert!(poly.is_zeroized());
}

// === === === === === === === === === ===
// tag_with_backend
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_tag_with_backend_returns_what_the_oracle_returns_at_the_widest(#[case] backend: Backend) {
    // Every part of this input is the largest it can be. The clamp takes the
    // top four bits of four bytes of `r` and the bottom two of three others,
    // so a key of all ones is the largest `r` it lets through — which makes
    // every one of the twenty-five partial products as wide as it gets, and
    // the carry chain across the five limbs of twenty-six bits as long. A
    // message of all ones adds the largest block there is before every
    // multiplication, and an `s` of all ones is the widest carry the final
    // addition can take.
    //
    // The published vectors go the other way: 5 through 11 push the reduction
    // with a small `r`. And a generator reaches all ones with a probability
    // nobody should plan around.
    let key = [0xffu8; KEY_SIZE];
    let message = std::vec![0xffu8; BLOCK_SIZE * 1000];
    let expected = oracle::tag(&key, &message);

    let mut tag = [0u8; TAG_SIZE];
    tag_with_backend(backend, &key, &message, &mut tag);

    assert_eq!(tag, expected);
}

proptest! {
    #[test]
    fn test_tag_with_backend_returns_what_the_oracle_returns(
        key: [u8; KEY_SIZE],
        message in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let expected = oracle::tag(&key, &message);

        let mut rust = [0u8; TAG_SIZE];
        let mut auto = [0u8; TAG_SIZE];

        tag_with_backend(Backend::Rust, &key, &message, &mut rust);
        tag_with_backend(Backend::Auto, &key, &message, &mut auto);

        prop_assert_eq!(rust, expected);
        prop_assert_eq!(auto, expected);
    }
}
