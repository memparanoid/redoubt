// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! A matrix formulation of the rounds, used only by tests.
//!
//! Rows are shifted between column rounds instead of spelling out the eight
//! index tuples the backends use. Each block starts from its absolute counter;
//! no mutable counter state is shared with the next block. Published answers
//! hold this implementation to the same definition as the backends.

use std::vec::Vec;

/// Twenty rounds, with the diagonal round expressed as shifted columns.
pub(crate) fn rounds(input: [u32; 16]) -> [u32; 16] {
    let mut rows = [[0u32; 4]; 4];

    for (row, words) in rows.iter_mut().zip(input.chunks_exact(4)) {
        row.copy_from_slice(words);
    }

    for _ in 0..10 {
        columns(&mut rows);

        for (at, row) in rows.iter_mut().enumerate().skip(1) {
            row.rotate_left(at);
        }

        columns(&mut rows);

        for (at, row) in rows.iter_mut().enumerate().skip(1) {
            row.rotate_right(at);
        }
    }

    core::array::from_fn(|at| rows[at / 4][at % 4])
}

/// Four independent quarter rounds, each on one column.
#[expect(
    clippy::needless_range_loop,
    reason = "Each column spans all four rows"
)]
fn columns(rows: &mut [[u32; 4]; 4]) {
    for col in 0..4 {
        let [mut a, mut b, mut c, mut d] = core::array::from_fn(|row| rows[row][col]);

        for (first, second) in [(16, 12), (8, 7)] {
            a = a.wrapping_add(b);
            d = (d ^ a).rotate_left(first);
            c = c.wrapping_add(d);
            b = (b ^ c).rotate_left(second);
        }

        for (row, value) in [a, b, c, d].into_iter().enumerate() {
            rows[row][col] = value;
        }
    }
}

/// A state assembled as bytes before it is interpreted as words.
fn state(key: &[u8; 32], suffix: &[u8; 16]) -> [u32; 16] {
    let mut bytes = [0u8; 64];
    bytes[..16].copy_from_slice(b"expand 32-byte k");
    bytes[16..48].copy_from_slice(key);
    bytes[48..].copy_from_slice(suffix);

    core::array::from_fn(|at| u32::from_le_bytes(bytes[at * 4..at * 4 + 4].try_into().unwrap()))
}

/// ChaCha20 with either nonce layout, one freshly built state per block.
pub(crate) fn xor(key: &[u8; 32], nonce: &[u8], counter: u64, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();

    for (at, chunk) in out.chunks_mut(64).enumerate() {
        let mut suffix = [0u8; 16];
        let counter = counter.checked_add(at as u64).unwrap();

        match nonce.len() {
            8 => suffix[..8].copy_from_slice(&counter.to_le_bytes()),
            12 => suffix[..4].copy_from_slice(&u32::try_from(counter).unwrap().to_le_bytes()),
            _ => panic!("ChaCha20 needs eight or twelve nonce bytes"),
        }

        suffix[16 - nonce.len()..].copy_from_slice(nonce);
        let initial = state(key, &suffix);
        let permuted = rounds(initial);
        let stream: Vec<u8> = initial
            .into_iter()
            .zip(permuted)
            .flat_map(|(before, after)| before.wrapping_add(after).to_le_bytes())
            .collect();

        for (byte, mask) in chunk.iter_mut().zip(stream) {
            *byte ^= mask;
        }
    }

    out
}

/// HChaCha20 keeps the outer two rows, without feed-forward.
pub(crate) fn subkey(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let permuted = rounds(state(key, nonce));
    let words = [0, 1, 2, 3, 12, 13, 14, 15];

    core::array::from_fn(|at| permuted[words[at / 4]].to_le_bytes()[at % 4])
}

/// XChaCha20 as the explicit composition the production seam keeps inside.
pub(crate) fn xxor(key: &[u8; 32], nonce: &[u8; 24], counter: u32, data: &[u8]) -> Vec<u8> {
    let derived = subkey(key, nonce[..16].try_into().unwrap());
    let mut short = [0u8; 12];
    short[4..].copy_from_slice(&nonce[16..]);

    xor(&derived, &short, u64::from(counter), data)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::super::vectors::{
        BLOCK, DHOLE, HNONCE, INITIAL, PERMUTED, SUBKEY, VECTORS, XCIPHERTEXT, XKEY, XNONCE,
        ZERO_BLOCK, hex,
    };
    use super::{columns, rounds, state, subkey, xor, xxor};

    // === === === === === === === === === ===
    // columns
    // === === === === === === === === === ===

    #[test]
    fn test_columns_returns_the_published_quarter_round() {
        // RFC 8439 §2.1.1 in every column. A zero column beside it also
        // catches a round that accidentally reads from its neighbour.
        for col in 0..4 {
            let mut rows = [[0u32; 4]; 4];

            for (row, value) in [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]
                .into_iter()
                .enumerate()
            {
                rows[row][col] = value;
            }

            columns(&mut rows);

            for (row, expected) in [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]
                .into_iter()
                .enumerate()
            {
                for (at, &value) in rows[row].iter().enumerate() {
                    assert_eq!(value, if at == col { expected } else { 0 });
                }
            }
        }
    }

    // === === === === === === === === === ===
    // state
    // === === === === === === === === === ===

    #[test]
    fn test_state_returns_the_published_initial_state() {
        let key = core::array::from_fn(|at| at as u8);
        let suffix = hex("01000000000000090000004a00000000");

        assert_eq!(state(&key, &suffix), INITIAL);
    }

    // === === === === === === === === === ===
    // rounds
    // === === === === === === === === === ===

    #[test]
    fn test_rounds_returns_the_published_intermediate_state() {
        assert_eq!(rounds(INITIAL), PERMUTED);
    }

    // === === === === === === === === === ===
    // xor
    // === === === === === === === === === ===

    #[test]
    fn test_xor_returns_the_published_block() {
        let key = core::array::from_fn(|at| at as u8);
        let nonce: [u8; 12] = hex("000000090000004a00000000");

        assert_eq!(xor(&key, &nonce, 1, &[0; 64]), hex::<64>(BLOCK));
    }

    #[rstest]
    #[case::ietf(12)]
    #[case::bernstein(8)]
    fn test_xor_returns_the_published_zero_block(#[case] nonce_len: usize) {
        assert_eq!(
            xor(&[0; 32], &[0; 12][..nonce_len], 0, &[0; 64]),
            hex::<64>(ZERO_BLOCK)
        );
    }

    #[test]
    fn test_xor_returns_the_published_ciphertext() {
        for vector in VECTORS {
            assert_eq!(
                xor(
                    &vector.key,
                    &vector.nonce,
                    u64::from(vector.counter),
                    vector.plaintext
                ),
                vector.ciphertext,
                "{}",
                vector.from,
            );
        }
    }

    #[test]
    fn test_xor_bernstein_places_the_high_counter_word_in_the_published_state() {
        // The RFC's first nonce word occupies the same state slot as the
        // original variant's high counter word. This is still the RFC's
        // published block, with a different interpretation of its inputs.
        let key = core::array::from_fn(|at| at as u8);
        let nonce: [u8; 8] = hex("0000004a00000000");

        assert_eq!(
            xor(&key, &nonce, 0x09000000_00000001, &[0; 64]),
            hex::<64>(BLOCK)
        );
    }

    #[test]
    fn test_xor_bernstein_carries_into_the_high_counter_word() {
        let key = core::array::from_fn(|at| at as u8);
        let nonce: [u8; 8] = hex("0000004a00000000");
        let before: [u8; 12] = hex("ffffff080000004a00000000");
        let after: [u8; 12] = hex("000000090000004a00000000");
        let actual = xor(&key, &nonce, 0x08ffffff_ffffffff, &[0; 192]);

        assert_eq!(
            &actual[..64],
            xor(&key, &before, u64::from(u32::MAX), &[0; 64])
        );
        assert_eq!(&actual[64..128], xor(&key, &after, 0, &[0; 64]));
        assert_eq!(&actual[128..], hex::<64>(BLOCK));
    }

    #[rstest]
    #[case::ietf(12, u64::from(u32::MAX))]
    #[case::bernstein(8, u64::MAX)]
    fn test_xor_accepts_empty_input_at_the_last_counter(
        #[case] nonce_len: usize,
        #[case] counter: u64,
    ) {
        assert!(xor(&[0; 32], &[0; 12][..nonce_len], counter, &[]).is_empty());
        assert_eq!(
            xor(&[0; 32], &[0; 12][..nonce_len], counter, &[0; 64]).len(),
            64
        );
    }

    #[test]
    fn test_xor_returns_every_prefix_of_the_published_ciphertext() {
        for vector in VECTORS {
            for length in 0..=vector.plaintext.len() {
                assert_eq!(
                    xor(
                        &vector.key,
                        &vector.nonce,
                        u64::from(vector.counter),
                        &vector.plaintext[..length]
                    ),
                    &vector.ciphertext[..length],
                    "{}, {length} bytes in",
                    vector.from,
                );
            }
        }
    }

    // === === === === === === === === === ===
    // subkey
    // === === === === === === === === === ===

    #[test]
    fn test_subkey_returns_the_published_subkey() {
        let key = core::array::from_fn(|at| at as u8);

        assert_eq!(subkey(&key, &hex(HNONCE)), hex::<32>(SUBKEY));
    }

    // === === === === === === === === === ===
    // xxor
    // === === === === === === === === === ===

    #[rstest]
    #[case::counter_zero(0)]
    #[case::counter_one(1)]
    fn test_xxor_returns_the_published_ciphertext(#[case] counter: u32) {
        let expected = hex::<304>(XCIPHERTEXT[counter as usize]);

        assert_eq!(xxor(&hex(XKEY), &hex(XNONCE), counter, DHOLE), expected);
        assert_eq!(xxor(&hex(XKEY), &hex(XNONCE), counter, &expected), DHOLE);
    }

    #[rstest]
    #[case::counter_zero(0)]
    #[case::counter_one(1)]
    fn test_xxor_returns_every_prefix_of_the_published_ciphertext(#[case] counter: u32) {
        let expected = hex::<304>(XCIPHERTEXT[counter as usize]);

        for length in 0..=DHOLE.len() {
            assert_eq!(
                xxor(&hex(XKEY), &hex(XNONCE), counter, &DHOLE[..length]),
                &expected[..length],
                "counter {counter}, {length} bytes in",
            );
        }
    }
}
