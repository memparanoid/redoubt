// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The compression, against the answers NIST published for the digest.
//!
//! # How a compression gets an oracle
//!
//! Nobody publishes answers for the compression on its own. What is published
//! is the digest, and a digest is this run over the padded message from the
//! starting state — so the padding and the chaining are done here, out of FIPS
//! 180-4, and the answer stays NIST's. That is what makes it a second
//! formulation rather than the implementation agreeing with itself.
//!
//! It is also the only thing in this crate that reaches a state which is not
//! the starting one. Every message of fifty-six bytes or more leaves no room
//! for the length field, so the padding takes a second block whose incoming
//! state is the first block's answer — and until this file existed, nothing
//! asked for that.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use rstest::rstest;

use redoubt_asm::Backend;

use crate::backend::sha256_compress_block;
use crate::consts::{BLOCK_SIZE, HASH_SIZE};

use crate::tests::{LONG_MSG, LONG_MSG_COUNT, SHORT_MSG, SHORT_MSG_COUNT, hex, messages};

/// The state a digest starts from, FIPS 180-4 §5.3.3.
///
/// Written out rather than read from the implementation: it is half of what the
/// compression is being held to, and taking it from the thing under test would
/// leave the two agreeing about it by construction.
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

// ============================================================================
// sha256_compress_block
// ============================================================================

/// Every length from no bits to a block and a half, one block at a time.
///
/// The lengths are what this is for: fifty-five bytes is the last that fits in
/// one block with its length field, and fifty-six is the first that does not.
/// Both sides of that line are in here.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_compress_block_answers_the_published_digest_for_every_short_message(
    #[case] backend: Backend,
) {
    for (message, digest) in messages(SHORT_MSG, SHORT_MSG_COUNT) {
        assert_eq!(
            compressed(backend, &message),
            digest,
            "{} bytes",
            message.len(),
        );
    }
}

/// Messages of 163 bytes to 6400, which is the chain run long enough that a
/// state carried wrongly from one block to the next has somewhere to show.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_compress_block_answers_the_published_digest_for_every_long_message(
    #[case] backend: Backend,
) {
    for (message, digest) in messages(LONG_MSG, LONG_MSG_COUNT) {
        assert_eq!(
            compressed(backend, &message),
            digest,
            "{} bytes",
            message.len(),
        );
    }
}
