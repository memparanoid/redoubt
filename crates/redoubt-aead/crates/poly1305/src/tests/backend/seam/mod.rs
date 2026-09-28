// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each function of the seam answers, asked of every backend the target
//! has, over a state the test holds itself.

use std::vec::Vec;

use proptest::prelude::*;
use rstest::rstest;

use redoubt_aead_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};
use redoubt_asm::Backend;

use crate::backend::{finalize, init, update};
use crate::consts::{ACC_WORDS, R_WORDS};

use crate::tests::support::{against_the_appendix, oracle};

/// RFC 8439 §2.5.1: the bits of `r` the clamp keeps.
const CLAMP: u128 = 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;

struct State {
    r: [u64; R_WORDS],
    s: [u8; BLOCK_SIZE],
    acc: [u64; ACC_WORDS],
    block: [u8; BLOCK_SIZE],
    filled: usize,
}

impl State {
    fn keyed(backend: Backend, key: &[u8; KEY_SIZE]) -> Self {
        let mut state = Self {
            r: [0; R_WORDS],
            s: [0; BLOCK_SIZE],
            acc: [0; ACC_WORDS],
            block: [0; BLOCK_SIZE],
            filled: 0,
        };

        init(backend, &mut state.r, &mut state.s, key);

        state
    }

    fn absorb(&mut self, backend: Backend, said: &[u8]) {
        update(
            backend,
            &mut self.acc,
            &self.r,
            &mut self.block,
            &mut self.filled,
            said,
        );
    }

    fn answer(&mut self, backend: Backend, said: &[u8]) -> [u8; TAG_SIZE] {
        let mut out = [0_u8; TAG_SIZE];

        finalize(backend, &mut self.acc, &self.r, &self.s, said, &mut out);

        out
    }

    fn answer_from_the_buffer(&mut self, backend: Backend) -> [u8; TAG_SIZE] {
        let block = self.block;

        self.answer(backend, &block[..self.filled])
    }
}

// === === === === === === === === === ===
// init
// === === === === === === === === === ===

proptest! {
    #[test]
    fn test_init_clamps_r_and_keeps_s_as_it_arrived(key: [u8; KEY_SIZE]) {
        let (low, high) = key.split_at(BLOCK_SIZE);
        let clamped = u128::from_le_bytes(low.try_into().expect("Infallible: sixteen of thirty-two")) & CLAMP;
        let r = [clamped as u64, (clamped >> 64) as u64];

        for backend in [Backend::Rust, Backend::Auto] {
            let state = State::keyed(backend, &key);

            prop_assert_eq!(state.r, r, "{:?}", backend);
            prop_assert_eq!(&state.s[..], high, "{:?}", backend);
        }
    }
}

// === === === === === === === === === ===
// update
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_update_returns_the_same_tag_at_every_split(#[case] backend: Backend) {
    let key = [0x5e; KEY_SIZE];
    let message: Vec<u8> = (0..70u16).map(|i| i as u8).collect();
    let whole = State::keyed(backend, &key).answer(backend, &message);

    for at in 0..=message.len() {
        let mut state = State::keyed(backend, &key);
        let (head, rest) = message.split_at(at);

        state.absorb(backend, head);
        state.absorb(backend, rest);

        assert_eq!(
            state.answer_from_the_buffer(backend),
            whole,
            "split at {at} of {}",
            message.len()
        );
    }
}

proptest! {
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
            let mut state = State::keyed(backend, &key);
            let mut from = 0;

            for &to in &offsets {
                state.absorb(backend, &message[from..to]);
                from = to;
            }

            state.absorb(backend, &message[from..]);

            prop_assert_eq!(
                state.answer_from_the_buffer(backend),
                expected,
                "{:?}, cut at {:?}",
                backend,
                offsets
            );
        }
    }
}

// === === === === === === === === === ===
// finalize
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_finalize_returns_the_appendix_tag(#[case] backend: Backend) {
    against_the_appendix(|key, message, out| {
        *out = State::keyed(backend, key).answer(backend, message);
    });
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_finalize_returns_what_the_oracle_returns_at_the_widest(#[case] backend: Backend) {
    // Every part of this input is the largest it can be. The clamp takes the
    // top four bits of four bytes of `r` and the bottom two of three others,
    // so a key of all ones is the largest `r` it lets through — which makes
    // every product of a word of `r` as wide as it gets, and every carry
    // between the words of the accumulator as long. A
    // message of all ones adds the largest block there is before every
    // multiplication, and an `s` of all ones is the widest carry the final
    // addition can take.
    //
    // The published vectors go the other way: 5 through 11 push the reduction
    // with a small `r`. And a generator reaches all ones with a probability
    // nobody should plan around.
    let key = [0xffu8; KEY_SIZE];
    let message = std::vec![0xffu8; BLOCK_SIZE * 1000];

    assert_eq!(
        State::keyed(backend, &key).answer(backend, &message),
        oracle::tag(&key, &message)
    );
}

proptest! {
    #[test]
    fn test_finalize_returns_what_the_oracle_returns(
        key: [u8; KEY_SIZE],
        message in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let expected = oracle::tag(&key, &message);

        for backend in [Backend::Rust, Backend::Auto] {
            prop_assert_eq!(
                State::keyed(backend, &key).answer(backend, &message),
                expected,
                "{:?}",
                backend
            );
        }
    }
}
