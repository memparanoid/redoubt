// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The arithmetic in Rust: what answers on a target nobody wrote assembly for,
//! and what the assembly is held against everywhere else.
//!
//! It answers the same and promises less. A block holds twenty-five products
//! and five sums, more than there are registers on most targets that get here,
//! so some go to a slot the compiler chose. Best effort, and named as such:
//! whether a value was ever in memory is not a thing the source says.
//!
//! That is also where the effort stops. The arrays below live in structs that
//! empty themselves on drop, because five `u64` are going to memory whatever
//! anybody wants; a single word mid-shift stays an expression, because giving
//! it a home is how you force into memory something that was in a register —
//! the wipe would create the slot it then clears.

use redoubt_zero::{FastZeroizable, RedoubtZero};

use redoubt_aead_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

use crate::consts::{LIMB_MASK, LIMBS};

/// The four words a sixteen-byte block is read as, and the products of one
/// multiplication by `r`.
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
struct BlockWork {
    /// The block as four words of thirty-two bits.
    words: [u32; 4],
    /// Each of the upper four limbs of `r` multiplied by five, which is what a
    /// limb above the fifth is worth once it wraps.
    folded: [u64; 4],
    /// The five sums, before they are carried back into the accumulator.
    sums: [u64; LIMBS],
}

/// The accumulator on its way to being a tag.
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
struct FinalWork {
    /// The accumulator, carried and then reduced.
    reduced: [u64; LIMBS],
    /// The accumulator plus five, which is the same number below the modulus
    /// whenever the accumulator was above it.
    above: [u64; 4],
    /// The answer as four words of thirty-two bits, before `s` is added.
    words: [u64; 4],
}

/// The last of the message, with the marker written after it.
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
struct TailWork {
    /// A whole block's worth, of which only the front came from the message.
    block: [u8; BLOCK_SIZE],
}

pub(crate) fn init(r: &mut [u32; LIMBS], s: &mut [u8; BLOCK_SIZE], key: &[u8; KEY_SIZE]) {
    let mut work = BlockWork::default();

    // RFC 8439 §2.5: the top half of four bytes goes, and the bottom two bits
    // of three others. What is left is short enough that a limb times it
    // cannot overflow the sums in `whole`.
    word(&mut work.words[0], &[key[0], key[1], key[2], key[3] & 0x0f]);
    word(
        &mut work.words[1],
        &[key[4] & 0xfc, key[5], key[6], key[7] & 0x0f],
    );
    word(
        &mut work.words[2],
        &[key[8] & 0xfc, key[9], key[10], key[11] & 0x0f],
    );
    word(
        &mut work.words[3],
        &[key[12] & 0xfc, key[13], key[14], key[15] & 0x0f],
    );

    spread(&mut work.sums, &work.words, 0);

    r[0] = work.sums[0] as u32;
    r[1] = work.sums[1] as u32;
    r[2] = work.sums[2] as u32;
    r[3] = work.sums[3] as u32;
    r[4] = work.sums[4] as u32;

    s.copy_from_slice(&key[BLOCK_SIZE..KEY_SIZE]);
}

pub(crate) fn update(
    acc: &mut [u64; LIMBS],
    r: &[u32; LIMBS],
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
    acc: &mut [u64; LIMBS],
    r: &[u32; LIMBS],
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
///
/// Where a message handed over in one piece goes through all of itself without
/// the bytes being copied anywhere in between.
fn straight_through(acc: &mut [u64; LIMBS], r: &[u32; LIMBS], said: &[u8]) -> usize {
    let mut at = 0;

    while at + BLOCK_SIZE <= said.len() {
        whole(
            acc,
            r,
            said[at..at + BLOCK_SIZE]
                .try_into()
                .expect("infallible: the slice is exactly 16 bytes"),
            1,
        );

        at += BLOCK_SIZE;
    }

    at
}

/// `acc = (acc + block) * r`, modulo 2^130 - 5.
fn whole(acc: &mut [u64; LIMBS], r: &[u32; LIMBS], block: &[u8; BLOCK_SIZE], hibit: u32) {
    let mut work = BlockWork::default();

    word(&mut work.words[0], &block[0..4]);
    word(&mut work.words[1], &block[4..8]);
    word(&mut work.words[2], &block[8..12]);
    word(&mut work.words[3], &block[12..16]);

    spread(&mut work.sums, &work.words, hibit);

    acc[0] += work.sums[0];
    acc[1] += work.sums[1];
    acc[2] += work.sums[2];
    acc[3] += work.sums[3];
    acc[4] += work.sums[4];

    // A product that lands above the fifth limb comes back down worth five
    // times less a power, because the modulus is 2^130 - 5. Taking that
    // multiplication now is what keeps it out of the sums.
    work.folded[0] = u64::from(r[1]) * 5;
    work.folded[1] = u64::from(r[2]) * 5;
    work.folded[2] = u64::from(r[3]) * 5;
    work.folded[3] = u64::from(r[4]) * 5;

    // Twenty-five products, gathered by which power of 2^26 they land on.
    work.sums[0] = acc[0] * u64::from(r[0])
        + acc[1] * work.folded[3]
        + acc[2] * work.folded[2]
        + acc[3] * work.folded[1]
        + acc[4] * work.folded[0];
    work.sums[1] = acc[0] * u64::from(r[1])
        + acc[1] * u64::from(r[0])
        + acc[2] * work.folded[3]
        + acc[3] * work.folded[2]
        + acc[4] * work.folded[1];
    work.sums[2] = acc[0] * u64::from(r[2])
        + acc[1] * u64::from(r[1])
        + acc[2] * u64::from(r[0])
        + acc[3] * work.folded[3]
        + acc[4] * work.folded[2];
    work.sums[3] = acc[0] * u64::from(r[3])
        + acc[1] * u64::from(r[2])
        + acc[2] * u64::from(r[1])
        + acc[3] * u64::from(r[0])
        + acc[4] * work.folded[3];
    work.sums[4] = acc[0] * u64::from(r[4])
        + acc[1] * u64::from(r[3])
        + acc[2] * u64::from(r[2])
        + acc[3] * u64::from(r[1])
        + acc[4] * u64::from(r[0]);

    carry(&mut work.sums);

    acc.copy_from_slice(&work.sums);
}

/// The accumulator reduced below the modulus, added to `s`, and written out.
fn settle(acc: &[u64; LIMBS], s: &[u8; BLOCK_SIZE], out: &mut [u8; TAG_SIZE]) {
    let mut work = FinalWork::default();

    work.reduced.copy_from_slice(acc);
    carry(&mut work.reduced);

    // The accumulator is now below 2^130 but may still be at or above the
    // modulus, and there is exactly one subtraction that could be owed. Adding
    // five says whether it is: if the sum carries past the hundred and
    // thirtieth bit, the accumulator was at least 2^130 - 5.
    work.above[0] = work.reduced[0] + 5;
    work.above[1] = work.reduced[1] + (work.above[0] >> 26);
    work.above[0] &= LIMB_MASK;
    work.above[2] = work.reduced[2] + (work.above[1] >> 26);
    work.above[1] &= LIMB_MASK;
    work.above[3] = work.reduced[3] + (work.above[2] >> 26);
    work.above[2] &= LIMB_MASK;

    // All ones where the accumulator was already below the modulus, and all
    // zeros where it was not. A comparison instead of a mask would be a branch
    // on the tag, which is a branch on the key that made it.
    let take_reduced = ((work.reduced[4] + (work.above[3] >> 26)) >> 26).wrapping_sub(1);
    work.above[3] &= LIMB_MASK;

    work.reduced[0] = (work.reduced[0] & take_reduced) | (work.above[0] & !take_reduced);
    work.reduced[1] = (work.reduced[1] & take_reduced) | (work.above[1] & !take_reduced);
    work.reduced[2] = (work.reduced[2] & take_reduced) | (work.above[2] & !take_reduced);
    work.reduced[3] = (work.reduced[3] & take_reduced) | (work.above[3] & !take_reduced);
    // The sum has no fifth limb, so where it is taken the fifth goes.
    work.reduced[4] &= take_reduced;

    // Five limbs of twenty-six into four words of thirty-two.
    work.words[0] = work.reduced[0] | (work.reduced[1] & 0x3f) << 26;
    work.words[1] = work.reduced[1] >> 6 | (work.reduced[2] & 0xfff) << 20;
    work.words[2] = work.reduced[2] >> 12 | (work.reduced[3] & 0x3_ffff) << 14;
    work.words[3] = work.reduced[3] >> 18 | (work.reduced[4] & 0xff_ffff) << 8;

    work.words[0] += u64::from(le_word(&s[0..4]));
    work.words[1] += u64::from(le_word(&s[4..8])) + (work.words[0] >> 32);
    work.words[2] += u64::from(le_word(&s[8..12])) + (work.words[1] >> 32);
    work.words[3] += u64::from(le_word(&s[12..16])) + (work.words[2] >> 32);

    out[0..4].copy_from_slice(&(work.words[0] as u32).to_le_bytes());
    out[4..8].copy_from_slice(&(work.words[1] as u32).to_le_bytes());
    out[8..12].copy_from_slice(&(work.words[2] as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(work.words[3] as u32).to_le_bytes());
}

/// The five limbs of the number four words spell, into `out`.
///
/// `hibit` is added above the hundred and twenty-eighth bit, which is where a
/// block's marker goes and where `r` has nothing.
fn spread(out: &mut [u64; LIMBS], words: &[u32; 4], hibit: u32) {
    out[0] = u64::from(words[0]) & LIMB_MASK;
    out[1] = u64::from(words[0] >> 26 | words[1] << 6) & LIMB_MASK;
    out[2] = u64::from(words[1] >> 20 | words[2] << 12) & LIMB_MASK;
    out[3] = u64::from(words[2] >> 14 | words[3] << 18) & LIMB_MASK;
    out[4] = u64::from(words[3] >> 8 | hibit << 24);
}

/// Every limb back under its twenty-six bits, and what ran off the top folded
/// back in worth five.
fn carry(limbs: &mut [u64; LIMBS]) {
    limbs[1] += limbs[0] >> 26;
    limbs[0] &= LIMB_MASK;
    limbs[2] += limbs[1] >> 26;
    limbs[1] &= LIMB_MASK;
    limbs[3] += limbs[2] >> 26;
    limbs[2] &= LIMB_MASK;
    limbs[4] += limbs[3] >> 26;
    limbs[3] &= LIMB_MASK;
    limbs[0] += (limbs[4] >> 26) * 5;
    limbs[4] &= LIMB_MASK;
    limbs[1] += limbs[0] >> 26;
    limbs[0] &= LIMB_MASK;
}

/// `dst` gets the little-endian word `bytes` spells.
fn word(dst: &mut u32, bytes: &[u8]) {
    *dst = u32::from(bytes[0])
        | u32::from(bytes[1]) << 8
        | u32::from(bytes[2]) << 16
        | u32::from(bytes[3]) << 24;
}

/// The little-endian word `bytes` spells.
///
/// The one thing here that hands a value back, and only `s` goes through it:
/// what it reads is added into the tag and leaves in it.
fn le_word(bytes: &[u8]) -> u32 {
    u32::from(bytes[0])
        | u32::from(bytes[1]) << 8
        | u32::from(bytes[2]) << 16
        | u32::from(bytes[3]) << 24
}
