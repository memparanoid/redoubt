// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The rounds in Rust: what answers on a target nobody wrote assembly for, and
//! what the assembly is held against everywhere else.
//!
//! It answers the same and promises less. Sixteen words is more than there are
//! registers on either of the targets that get here, so the state lives in a
//! slot the compiler chose for the whole of the twenty rounds. Best effort, and
//! named as such: what is below empties the slot it named, and cannot empty the
//! copies the compiler may have made of it.

use redoubt_zero::{FastZeroizable, RedoubtZero};

use redoubt_aead_v2_core::consts::chacha::{
    BLOCK_SIZE, HNONCE_SIZE, KEY_SIZE, NONCE_SIZE, XNONCE_SIZE,
};

use crate::consts::{COUNTER_AT, DOUBLE_ROUNDS, KEY_AT, PREAMBLE, WORDS};

/// One block's worth of everything an operation needs.
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
struct Work {
    /// The state as it was built, kept because the rounds are added back to it.
    initial: [u32; WORDS],
    /// The state the rounds are run on.
    working: [u32; WORDS],
    /// The block that comes out.
    keystream: [u8; BLOCK_SIZE],
}

impl Default for Work {
    fn default() -> Self {
        Self {
            initial: [0; WORDS],
            working: [0; WORDS],
            keystream: [0; BLOCK_SIZE],
        }
    }
}

/// The subkey HChaCha20 derives, which is what lets a nonce be twenty-four
/// bytes long.
pub(crate) fn subkey(out: &mut [u8; KEY_SIZE], key: &[u8; KEY_SIZE], nonce: &[u8; HNONCE_SIZE]) {
    let mut work = Work::default();

    work.working[..KEY_AT].copy_from_slice(&PREAMBLE);
    spread_key(&mut work.working, key);

    for at in 0..4 {
        word(
            &mut work.working[COUNTER_AT + at],
            &nonce[at * 4..at * 4 + 4],
        );
    }

    rounds(&mut work.working);

    // The first four words and the last four, and nothing of the eight in
    // between — which is where the key went, and is the whole reason this is a
    // derivation and not a permutation anybody can undo.
    for at in 0..4 {
        out[at * 4..at * 4 + 4].copy_from_slice(&work.working[at].to_le_bytes());
        out[16 + at * 4..16 + at * 4 + 4]
            .copy_from_slice(&work.working[COUNTER_AT + at].to_le_bytes());
    }
}

/// `data` xored with the keystream that starts at `counter`.
///
/// The nonce says which variant this is: twelve bytes is RFC 8439 with a
/// counter of thirty-two bits, and eight is Bernstein's original with a counter
/// of sixty-four.
pub(crate) fn xor(key: &[u8; KEY_SIZE], nonce: &[u8], counter: u64, data: &mut [u8]) {
    let mut work = Work::default();

    build(&mut work.initial, key, nonce, counter);

    for (at, chunk) in data.chunks_mut(BLOCK_SIZE).enumerate() {
        step(&mut work.initial, nonce.len(), at as u64);
        block(&mut work);

        for (byte, from) in chunk.iter_mut().zip(work.keystream.iter()) {
            *byte ^= from;
        }
    }
}

/// The same, under the subkey a twenty-four byte nonce derives.
///
/// The subkey is made and used here and never handed back, which is the reason
/// this exists rather than the caller composing the two above.
pub(crate) fn xxor(key: &[u8; KEY_SIZE], nonce: &[u8; XNONCE_SIZE], counter: u64, data: &mut [u8]) {
    let mut derived = Derived::default();

    subkey(
        &mut derived.key,
        key,
        nonce[..HNONCE_SIZE]
            .try_into()
            .expect("infallible: nonce[0..16] is exactly 16 bytes"),
    );

    // Four zero bytes and then what is left of the nonce, which is how the
    // draft says a twenty-four byte nonce becomes a twelve byte one.
    derived.nonce[4..NONCE_SIZE].copy_from_slice(&nonce[HNONCE_SIZE..XNONCE_SIZE]);

    xor(&derived.key, &derived.nonce, counter, data);
}

/// The subkey and the nonce it is used with, for as long as one block takes.
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
struct Derived {
    key: [u8; KEY_SIZE],
    nonce: [u8; NONCE_SIZE],
}

impl Default for Derived {
    fn default() -> Self {
        Self {
            key: [0; KEY_SIZE],
            nonce: [0; NONCE_SIZE],
        }
    }
}

/// The twenty rounds, on a state somebody else built.
///
/// Reachable on its own for the one published answer that is an intermediate:
/// RFC 8439 §2.3.2 prints the state after the rounds and before it is added
/// back, which nothing that returns a keystream can be held to.
#[cfg_attr(not(any(test, feature = "test-utils")), allow(dead_code))]
pub(crate) fn rounds(state: &mut [u32; WORDS]) {
    for _ in 0..DOUBLE_ROUNDS {
        quarter(state, 0, 4, 8, 12);
        quarter(state, 1, 5, 9, 13);
        quarter(state, 2, 6, 10, 14);
        quarter(state, 3, 7, 11, 15);

        quarter(state, 0, 5, 10, 15);
        quarter(state, 1, 6, 11, 12);
        quarter(state, 2, 7, 8, 13);
        quarter(state, 3, 4, 9, 14);
    }
}

/// The state for a key, a nonce and the first block's counter.
fn build(initial: &mut [u32; WORDS], key: &[u8; KEY_SIZE], nonce: &[u8], counter: u64) {
    initial[..KEY_AT].copy_from_slice(&PREAMBLE);
    spread_key(initial, key);

    if nonce.len() == NONCE_SIZE {
        initial[COUNTER_AT] = counter as u32;

        for at in 0..3 {
            word(
                &mut initial[COUNTER_AT + 1 + at],
                &nonce[at * 4..at * 4 + 4],
            );
        }
    } else {
        initial[COUNTER_AT] = counter as u32;
        initial[COUNTER_AT + 1] = (counter >> 32) as u32;

        for at in 0..2 {
            word(
                &mut initial[COUNTER_AT + 2 + at],
                &nonce[at * 4..at * 4 + 4],
            );
        }
    }
}

/// The counter moved `by` blocks past where `build` put it.
///
/// A whole state rebuilt per block would spread the key again every time, and
/// the key is the one thing in there that does not change.
fn step(initial: &mut [u32; WORDS], nonce_len: usize, by: u64) {
    if nonce_len == NONCE_SIZE {
        initial[COUNTER_AT] = initial[COUNTER_AT].wrapping_add(by as u32);
    } else {
        let moved = (u64::from(initial[COUNTER_AT + 1]) << 32 | u64::from(initial[COUNTER_AT]))
            .wrapping_add(by);

        initial[COUNTER_AT] = moved as u32;
        initial[COUNTER_AT + 1] = (moved >> 32) as u32;
    }
}

/// One keystream block from the state as it stands.
fn block(work: &mut Work) {
    work.working.copy_from_slice(&work.initial);

    rounds(&mut work.working);

    for at in 0..WORDS {
        work.working[at] = work.working[at].wrapping_add(work.initial[at]);

        work.keystream[at * 4..at * 4 + 4].copy_from_slice(&work.working[at].to_le_bytes());
    }
}

/// The eight key words into the state.
fn spread_key(state: &mut [u32; WORDS], key: &[u8; KEY_SIZE]) {
    for at in 0..8 {
        word(&mut state[KEY_AT + at], &key[at * 4..at * 4 + 4]);
    }
}

/// The quarter round of RFC 8439 §2.1, in place.
fn quarter(state: &mut [u32; WORDS], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// `dst` gets the little-endian word `bytes` spells.
fn word(dst: &mut u32, bytes: &[u8]) {
    *dst = u32::from(bytes[0])
        | u32::from(bytes[1]) << 8
        | u32::from(bytes[2]) << 16
        | u32::from(bytes[3]) << 24;
}
