// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The digest, against the answers NIST published for it.
//!
//! The files are read as they were published rather than turned into Rust. A
//! generated table is a second thing that can be wrong, and the parsing a
//! `.rsp` needs is three fields off lines that read `Name = value`.

use alloc::string::String;
use alloc::vec::Vec;

use rstest::rstest;

use redoubt_asm::Backend;

use crate::backend::sha256_hash;
use crate::consts::HASH_SIZE;

use crate::tests::{
    CHAINED, LONG_MSG, LONG_MSG_COUNT, MONTE, MONTE_COUNT, SHORT_MSG, SHORT_MSG_COUNT, field,
    from_hex, hex, messages,
};

/// The digest of a message, as the hex the file gives its answer in.
fn digest_of(backend: Backend, message: &[u8]) -> String {
    let mut out = [0_u8; HASH_SIZE];

    sha256_hash(backend, message, &mut out);

    hex(&out)
}

// ============================================================================
// sha256_hash
// ============================================================================

/// Every length from no bits to a block and a half, one at a time, which is
/// every decision the padding makes and both sides of each.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hash_answers_the_published_digest_for_every_short_message(#[case] backend: Backend) {
    for (message, digest) in messages(SHORT_MSG, SHORT_MSG_COUNT) {
        assert_eq!(
            digest_of(backend, &message),
            digest,
            "{} bytes",
            message.len(),
        );
    }
}

/// Messages of 163 bytes to 6400, which is the block loop run long.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hash_answers_the_published_digest_for_every_long_message(#[case] backend: Backend) {
    for (message, digest) in messages(LONG_MSG, LONG_MSG_COUNT) {
        assert_eq!(
            digest_of(backend, &message),
            digest,
            "{} bytes",
            message.len(),
        );
    }
}

/// The Monte Carlo: a seed, and then a hundred thousand digests each taken of
/// the three before it, with the answer published every thousandth.
///
/// What this reaches that a list of messages does not is depth. Every digest is
/// the input to the next, so a bit that comes out wrong once comes out wrong in
/// everything after it, and the checkpoint says so.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hash_answers_the_published_checkpoints_of_the_monte_carlo(#[case] backend: Backend) {
    let seed = field(MONTE, "Seed");
    let checkpoints = field(MONTE, "MD");

    assert_eq!(seed.len(), 1, "the file starts from one seed");
    assert_eq!(checkpoints.len(), MONTE_COUNT, "the file is not all there");

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

        assert_eq!(hex(&window[2]), *checkpoint, "checkpoint {at}");

        // The next thousand start from the one that just came out.
        window = [window[2].clone(), window[2].clone(), window[2].clone()];
    }
}
