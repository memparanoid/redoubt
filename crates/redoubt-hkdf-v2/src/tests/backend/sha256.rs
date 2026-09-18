// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The Secure Hash Algorithm Validation System, which is the largest set of
//! answers for SHA-256 anybody published.
//!
//! The files are read as they were published rather than turned into Rust. A
//! generated table is a second thing that can be wrong, and the parsing a
//! `.rsp` needs is three fields off lines that read `Name = value`.
//!
//! # How the compression gets an oracle
//!
//! Nobody publishes answers for a compression on its own. What is published is
//! the digest, and a digest is the compression run over the padded message from
//! the starting state — so the padding and the chaining are done here, out of
//! FIPS 180-4, and the answer is still NIST's. That is what makes it a second
//! formulation rather than the implementation agreeing with itself.
//!
//! It is also the only thing that reaches a state that is not the starting one:
//! every message past fifty-five bytes takes a second block whose incoming
//! state is the first one's answer, and nothing else in this crate asks for
//! that.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use redoubt_asm::Backend;

use crate::backend::{sha256_compress_block, sha256_hash};
use crate::consts::{BLOCK_SIZE, HASH_SIZE};

use super::super::{
    CHAINED, LONG_MSG, LONG_MSG_COUNT, MONTE, MONTE_COUNT, SHORT_MSG, SHORT_MSG_COUNT, from_hex,
    hex,
};

/// The state a digest starts from, FIPS 180-4 §5.3.3.
///
/// Written here rather than read from the implementation: it is half of what
/// the compression is being held to, and taking it from the thing under test
/// would leave the two agreeing about it by construction.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The value of every `Name = value` line with that name.
///
/// The names that matter are distinct in their first characters, so a prefix is
/// enough to tell them apart and the header lines match none of them.
fn field<'a>(said: &'a str, name: &str) -> Vec<&'a str> {
    said.lines()
        .filter_map(|line| line.trim().strip_prefix(name))
        .filter_map(|rest| rest.trim_start().strip_prefix('='))
        .map(str::trim)
        .collect()
}

/// Every message of a file with the answer published for it.
fn messages(file: &str, counted: usize) -> Vec<(Vec<u8>, String)> {
    let lengths = field(file, "Len");
    let said = field(file, "Msg");
    let digests = field(file, "MD");

    assert_eq!(lengths.len(), counted, "the file is not all there");
    assert_eq!(said.len(), counted, "a message has no length or no answer");
    assert_eq!(digests.len(), counted, "a message has no answer");

    lengths
        .iter()
        .zip(&said)
        .zip(&digests)
        .map(|((length, message), digest)| {
            let bits: usize = length.parse().expect("a length is a number of bits");

            // The file writes one zero byte where the message is no bytes at
            // all.
            let message = if bits == 0 {
                Vec::new()
            } else {
                from_hex(message)
            };

            assert_eq!(
                message.len() * 8,
                bits,
                "the message is not the length it says"
            );

            (message, String::from(*digest))
        })
        .collect()
}

/// A message with the padding FIPS 180-4 §5.1.1 puts after it: a one bit, then
/// zeros, then the length in bits as sixty-four big-endian.
fn padded(message: &[u8]) -> Vec<u8> {
    let bits = (message.len() as u64) * 8;

    let mut block = Vec::from(message);

    block.push(0x80);

    while !(block.len() + 8).is_multiple_of(BLOCK_SIZE) {
        block.push(0);
    }

    block.extend_from_slice(&bits.to_be_bytes());

    block
}

/// The digest of a message, taken one block at a time through the compression.
fn compressed(backend: Backend, message: &[u8]) -> String {
    let mut state = H0;

    for block in padded(message).chunks_exact(BLOCK_SIZE) {
        let block: &[u8; BLOCK_SIZE] = block
            .try_into()
            .expect("Infallible: chunks_exact yields nothing but full chunks");

        sha256_compress_block(backend, &mut state, block);
    }

    let mut out = vec![0_u8; HASH_SIZE];

    for (word, into) in state.iter().zip(out.chunks_exact_mut(4)) {
        into.copy_from_slice(&word.to_be_bytes());
    }

    hex(&out)
}

/// The digest of a message, as the hex the file gives its answer in.
fn digest_of(backend: Backend, message: &[u8]) -> String {
    let mut out = [0_u8; HASH_SIZE];

    sha256_hash(backend, message, &mut out);

    hex(&out)
}

// ============================================================================
// sha256_compress_block
// ============================================================================

/// Every length from no bits to a block and a half, one block at a time.
///
/// Where the answers are the same as the digest's and what they reach is not:
/// a message of fifty-six bytes or more has no room left for the length field,
/// so the padding takes a second block and the compression is asked for the
/// first time with a state nobody chose.
#[test]
fn test_compress_block_answers_the_published_digest_for_every_short_message() {
    for backend in [Backend::Rust, Backend::Auto] {
        for (message, digest) in messages(SHORT_MSG, SHORT_MSG_COUNT) {
            assert_eq!(
                compressed(backend, &message),
                digest,
                "{} bytes, {backend:?}",
                message.len(),
            );
        }
    }
}

/// Messages of 163 bytes to 6400, which is the chain run long enough that a
/// state carried wrongly from one block to the next has somewhere to show.
#[test]
fn test_compress_block_answers_the_published_digest_for_every_long_message() {
    for backend in [Backend::Rust, Backend::Auto] {
        for (message, digest) in messages(LONG_MSG, LONG_MSG_COUNT) {
            assert_eq!(
                compressed(backend, &message),
                digest,
                "{} bytes, {backend:?}",
                message.len(),
            );
        }
    }
}

// ============================================================================
// sha256_hash
// ============================================================================

/// Every length from no bits to a block and a half, one at a time, which is
/// every decision the padding makes and both sides of each.
#[test]
fn test_hash_answers_the_published_digest_for_every_short_message() {
    for backend in [Backend::Rust, Backend::Auto] {
        for (message, digest) in messages(SHORT_MSG, SHORT_MSG_COUNT) {
            assert_eq!(
                digest_of(backend, &message),
                digest,
                "{} bytes, {backend:?}",
                message.len(),
            );
        }
    }
}

/// Messages of 163 bytes to 6400, which is the block loop run long.
#[test]
fn test_hash_answers_the_published_digest_for_every_long_message() {
    for backend in [Backend::Rust, Backend::Auto] {
        for (message, digest) in messages(LONG_MSG, LONG_MSG_COUNT) {
            assert_eq!(
                digest_of(backend, &message),
                digest,
                "{} bytes, {backend:?}",
                message.len(),
            );
        }
    }
}

/// The Monte Carlo: a seed, and then a hundred thousand digests each taken of
/// the three before it, with the answer published every thousandth.
///
/// What this reaches that a list of messages does not is depth. Every digest is
/// the input to the next, so a bit that comes out wrong once comes out wrong in
/// everything after it, and the checkpoint says so.
#[test]
fn test_hash_answers_the_published_checkpoints_of_the_monte_carlo() {
    let seed = field(MONTE, "Seed");
    let checkpoints = field(MONTE, "MD");

    assert_eq!(seed.len(), 1, "the file starts from one seed");
    assert_eq!(checkpoints.len(), MONTE_COUNT, "the file is not all there");

    for backend in [Backend::Rust, Backend::Auto] {
        let mut window = [from_hex(seed[0]), from_hex(seed[0]), from_hex(seed[0])];

        for (at, checkpoint) in checkpoints.iter().enumerate() {
            for _ in 0..CHAINED {
                let said: Vec<u8> = window.concat();
                let mut out = [0_u8; HASH_SIZE];

                sha256_hash(backend, &said, &mut out);

                window = [
                    core::mem::take(&mut window[1]),
                    core::mem::take(&mut window[2]),
                    Vec::from(out),
                ];
            }

            assert_eq!(hex(&window[2]), *checkpoint, "checkpoint {at}, {backend:?}");

            // The next thousand start from the one that just came out.
            window = [window[2].clone(), window[2].clone(), window[2].clone()];
        }
    }
}
