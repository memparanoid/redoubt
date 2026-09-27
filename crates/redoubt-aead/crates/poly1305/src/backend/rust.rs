// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The arithmetic in Rust: what answers on a target nobody wrote assembly for,
//! and what the assembly is held against everywhere else.
//!
//! It answers the same and promises less. The products are `u128`, which on a
//! target with no widening multiply is a call, and whatever the compiler spills
//! goes to a slot it chose. Best effort, and named as such: the words below live
//! in structs that empty themselves on drop, and a single word mid-sum stays an
//! expression, because giving it a home would put in memory what was in a
//! register.

use redoubt_zero::{FastZeroizable, RedoubtZero};

use redoubt_aead_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

use crate::consts::{ACC_WORDS, R_WORDS};

/// The accumulator with a block added, and the two sums it is multiplied into.
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
struct BlockWork {
    h: [u64; ACC_WORDS],
    d: [u128; 2],
}

/// The accumulator, the same plus five, and then the tag.
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
struct FinalWork {
    h: [u64; ACC_WORDS],
    g: [u64; ACC_WORDS],
}

/// The last of the message, with the marker written after it.
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
struct TailWork {
    block: [u8; BLOCK_SIZE],
}

pub(crate) fn init(r: &mut [u64; R_WORDS], s: &mut [u8; BLOCK_SIZE], key: &[u8; KEY_SIZE]) {
    // RFC 8439 §2.5: the top four bits of four bytes go, and the bottom two of
    // three others, as one mask over each half.
    r[0] = le_u64(&key[0..8]) & 0x0fff_fffc_0fff_ffff;
    r[1] = le_u64(&key[8..16]) & 0x0fff_fffc_0fff_fffc;

    s.copy_from_slice(&key[BLOCK_SIZE..KEY_SIZE]);
}

pub(crate) fn update(
    acc: &mut [u64; ACC_WORDS],
    r: &[u64; R_WORDS],
    block: &mut [u8; BLOCK_SIZE],
    filled: &mut usize,
    said: &[u8],
) {
    let mut at = 0;

    if *filled > 0 {
        let take = core::cmp::min(BLOCK_SIZE - *filled, said.len());

        block[*filled..*filled + take].copy_from_slice(&said[..take]);
        *filled += take;
        at = take;

        if *filled == BLOCK_SIZE {
            whole(acc, r, block, 1);
            block.fast_zeroize();
            *filled = 0;
        }
    }

    at += straight_through(acc, r, &said[at..]);

    if at < said.len() {
        *filled = said.len() - at;
        block[..*filled].copy_from_slice(&said[at..]);
    }
}

pub(crate) fn finalize(
    acc: &mut [u64; ACC_WORDS],
    r: &[u64; R_WORDS],
    s: &[u8; BLOCK_SIZE],
    said: &[u8],
    out: &mut [u8; TAG_SIZE],
) {
    let at = straight_through(acc, r, said);

    if at < said.len() {
        let mut work = TailWork::default();
        let rest = said.len() - at;

        work.block[..rest].copy_from_slice(&said[at..]);
        // The one above the message, which is what keeps a tail of zeros from
        // reading as a shorter message that ended sooner.
        work.block[rest] = 0x01;

        whole(acc, r, &work.block, 0);
    }

    settle(acc, s, out);
}

/// Every whole block of `said` into the accumulator, and how many bytes that
/// was.
fn straight_through(acc: &mut [u64; ACC_WORDS], r: &[u64; R_WORDS], said: &[u8]) -> usize {
    let mut at = 0;

    while at + BLOCK_SIZE <= said.len() {
        whole(
            acc,
            r,
            said[at..at + BLOCK_SIZE]
                .try_into()
                .expect("Infallible: the slice is exactly 16 bytes"),
            1,
        );

        at += BLOCK_SIZE;
    }

    at
}

/// `acc = (acc + block + hibit·2^128) · r`, reduced only as far as the next
/// block needs: the third word keeps two bits and whatever the last carry
/// brings.
fn whole(acc: &mut [u64; ACC_WORDS], r: &[u64; R_WORDS], block: &[u8; BLOCK_SIZE], hibit: u64) {
    let mut work = BlockWork::default();

    work.d[0] = u128::from(acc[0]) + u128::from(le_u64(&block[0..8]));
    work.d[1] = u128::from(acc[1]) + (work.d[0] >> 64) + u128::from(le_u64(&block[8..16]));
    work.h[0] = work.d[0] as u64;
    work.h[1] = work.d[1] as u64;
    work.h[2] = acc[2] + (work.d[1] >> 64) as u64 + hibit;

    // A product with r1 that lands on 2^128 wraps: 2^130 is 5 modulo the
    // prime, and the clamp leaves the bottom two bits of r1 empty, so
    // r1·2^128 = (r1/4)·2^130 comes back as r1 + r1/4 exactly.
    let s1 = r[1] + (r[1] >> 2);

    work.d[0] = u128::from(work.h[0]) * u128::from(r[0]) + u128::from(work.h[1]) * u128::from(s1);
    work.d[1] = u128::from(work.h[0]) * u128::from(r[1])
        + u128::from(work.h[1]) * u128::from(r[0])
        + u128::from(work.h[2]) * u128::from(s1);
    work.h[2] *= r[0];

    work.h[0] = work.d[0] as u64;
    work.d[1] += work.d[0] >> 64;
    work.h[1] = work.d[1] as u64;
    work.h[2] += (work.d[1] >> 64) as u64;

    // What stands at or above 2^130 comes back down worth five.
    let folded = (work.h[2] >> 2) * 5;
    work.h[2] &= 3;

    work.d[0] = u128::from(work.h[0]) + u128::from(folded);
    work.d[1] = u128::from(work.h[1]) + (work.d[0] >> 64);

    acc[0] = work.d[0] as u64;
    acc[1] = work.d[1] as u64;
    acc[2] = work.h[2] + (work.d[1] >> 64) as u64;
}

/// The accumulator reduced below the modulus, added to `s`, and written out.
fn settle(acc: &[u64; ACC_WORDS], s: &[u8; BLOCK_SIZE], out: &mut [u8; TAG_SIZE]) {
    let mut work = FinalWork::default();

    work.h.copy_from_slice(acc);

    // At most one subtraction of the modulus is owed, and adding five says
    // whether: the sum reaches 2^130 exactly when the accumulator was at least
    // 2^130 - 5, and then the sum's low 130 bits are the difference.
    let t = u128::from(work.h[0]) + 5;
    work.g[0] = t as u64;
    let t = u128::from(work.h[1]) + (t >> 64);
    work.g[1] = t as u64;
    work.g[2] = work.h[2] + (t >> 64) as u64;

    // All ones where the difference is taken, all zeros where it is not. A
    // comparison instead of a mask would be a branch on the tag, which is a
    // branch on the key that made it.
    let take_above = 0u64.wrapping_sub(work.g[2] >> 2);

    work.h[0] = (work.h[0] & !take_above) | (work.g[0] & take_above);
    work.h[1] = (work.h[1] & !take_above) | (work.g[1] & take_above);

    // + s, modulo 2^128: the carry out of the second word is dropped.
    let t = u128::from(work.h[0]) + u128::from(le_u64(&s[0..8]));
    work.g[0] = t as u64;
    work.g[1] = (u128::from(work.h[1]) + (t >> 64) + u128::from(le_u64(&s[8..16]))) as u64;

    out[0..8].copy_from_slice(&work.g[0].to_le_bytes());
    out[8..16].copy_from_slice(&work.g[1].to_le_bytes());
}

/// The little-endian word eight bytes spell.
fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(
        bytes
            .try_into()
            .expect("Infallible: every caller hands exactly 8 bytes"),
    )
}
