// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Every derivation libsodium was asked for, against the same one made here.
//!
//! The published vectors pin the inputs somebody thought to write down. What
//! they leave open is every length in between, and one of those is where this
//! crate is most likely to be wrong: `info` is read out of the caller's memory
//! and folded into a block buffer a piece at a time, so a length that ends
//! exactly on a block boundary takes a different path from one that does not.
//!
//! So the whole cross product is walked, and the answers come from libsodium.
//! Carrying a quarter of a million of them would be a file nobody reads, so
//! what is carried is one digest per info length: the SHA-256 of every output
//! of that row, concatenated.
//!
//! Nothing here is transcribed. Every input is derived from a seed that is
//! itself the digest of an ASCII string, so the two sides cannot drift by a
//! mistyped byte — only by walking the enumeration in a different order, which
//! is why the order is written in both of them.
//!
//! A row that goes red is not necessarily this crate: the file is generated
//! from the enumeration below, so a length added to it turns every row red
//! until the file is generated again. It has to be generated from libsodium.
//! Generated from this crate, it would freeze whatever this crate does today
//! and go on passing for ever.

use alloc::vec;
use alloc::vec::Vec;

use rstest::rstest;

use redoubt_asm::Backend;

use crate::backend::{hkdf_sha256, sha256_hash};
use crate::consts::HASH_SIZE;

use super::{MD_COUNT, SODIUM_DIGESTS, field, hex};

/// The enumeration, in the order both sides walk it.
///
/// A length added to any of these is a file that has to be generated again.
const INFO_LENGTHS: core::ops::Range<usize> = 0..131;
const SALT_LENGTHS: [usize; 12] = [0, 1, 31, 32, 33, 63, 64, 65, 96, 127, 128, 129];
const IKM_LENGTHS: [usize; 13] = [0, 1, 31, 32, 33, 63, 64, 65, 96, 127, 128, 129, 255];
const OKM_LENGTHS: [usize; 12] = [1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 255, 1024];

/// Which field the material is for, spelled as the generator spells it.
///
/// The word goes into the seed, so a different spelling is a different corpus.
#[derive(Clone, Copy)]
enum Field {
    Ikm,
    Salt,
    Info,
}

impl Field {
    const fn said(self) -> &'static [u8] {
        match self {
            Self::Ikm => b"ikm",
            Self::Salt => b"salt",
            Self::Info => b"info",
        }
    }
}

/// A field's seed, derived so that there is no hexadecimal to transcribe.
fn seed(field: Field) -> [u8; HASH_SIZE] {
    let mut said = Vec::from(b"redoubt-hkdf-sha256 corpus ".as_slice());
    said.extend_from_slice(field.said());

    let mut out = [0_u8; HASH_SIZE];
    sha256_hash(Backend::Rust, &said, &mut out);

    out
}

/// The bytes this field takes at this length.
///
/// Always through the Rust backend, whichever backend the case is about: the
/// two cases have to be handed the same inputs, or they are not two readings of
/// one thing.
fn material(field: Field, length: usize) -> Vec<u8> {
    let seed = seed(field);
    let mut said = Vec::with_capacity(length + HASH_SIZE);
    let mut counter = 0_u32;

    while said.len() < length {
        let mut block = Vec::with_capacity(HASH_SIZE + 8);
        block.extend_from_slice(&seed);
        block.extend_from_slice(&(length as u32).to_be_bytes());
        block.extend_from_slice(&counter.to_be_bytes());

        let mut digest = [0_u8; HASH_SIZE];
        sha256_hash(Backend::Rust, &block, &mut digest);

        said.extend_from_slice(&digest);
        counter += 1;
    }

    said.truncate(length);

    said
}

/// The digest published for each info length, in the order they were written.
fn published() -> Vec<(usize, &'static str)> {
    let lengths = field(SODIUM_DIGESTS, "Info");
    let digests = field(SODIUM_DIGESTS, "MD");

    assert_eq!(lengths.len(), MD_COUNT, "the file is not all there");
    assert_eq!(digests.len(), MD_COUNT, "a row has no answer");

    lengths
        .iter()
        .zip(&digests)
        .map(|(length, digest)| (length.parse().expect("an info length is a number"), *digest))
        .collect()
}

/// One row: every derivation of that info length, folded into one digest.
fn row(backend: Backend, info: &[u8]) -> [u8; HASH_SIZE] {
    let widest = OKM_LENGTHS.iter().copied().max().expect("a widest output");
    let mut okm = vec![0_u8; widest];
    let mut said = Vec::new();

    for &salt_len in &SALT_LENGTHS {
        let salt = material(Field::Salt, salt_len);

        for &ikm_len in &IKM_LENGTHS {
            let ikm = material(Field::Ikm, ikm_len);

            for &okm_len in &OKM_LENGTHS {
                hkdf_sha256(backend, &salt, &ikm, info, &mut okm[..okm_len]);
                said.extend_from_slice(&okm[..okm_len]);
            }
        }
    }

    let mut digest = [0_u8; HASH_SIZE];
    sha256_hash(Backend::Rust, &said, &mut digest);

    digest
}

// === === === === === === === === === ===
// What both sides have to agree on
// === === === === === === === === === ===
//
// Nothing here calls the algorithm. What is asked is whether the walk this file
// makes is the walk the generator made, because everything below rests on that
// and neither side can see the other. A difference in any of it reads as the
// crate being wrong at every length at once, which is the one failure worth
// telling apart from a real one.

/// The seeds are what every input is made of, and these are the ones the
/// generator printed.
///
/// Without this, a seed that drifted on either side would turn every row red at
/// once, and the file would read as though the crate were wrong at every
/// length. Written down here, the same drift is one failed test naming the
/// field that moved.
#[test]
fn test_the_seeds_are_the_ones_the_file_was_generated_from() {
    assert_eq!(
        hex(&seed(Field::Ikm)),
        "e44ba950fd9966211b21ee7a4438e616aa40958442a600a3acc48cafbee97796",
        "ikm"
    );
    assert_eq!(
        hex(&seed(Field::Salt)),
        "20b783ccbb8fb2a35ed954fdab0fec12b7e79d78c02ca44141563fdd8e3bf604",
        "salt"
    );
    assert_eq!(
        hex(&seed(Field::Info)),
        "2d2a2ff97810ff06058a5c2765875d0325afc20f6a049c46c2689c4ab76eea14",
        "info"
    );
}

/// The material of one length is not a prefix of the material of a longer one.
///
/// Both sides derive it and neither compares it, so a difference in this would
/// show up as every row red at once. What that would look like is the crate
/// being wrong at every length, which is the one failure worth telling apart
/// from a real one.
#[test]
fn test_a_length_does_not_prefix_a_longer_one() {
    let short = material(Field::Info, 32);
    let long = material(Field::Info, 64);

    assert_ne!(short[..], long[..32], "the length is not in the derivation");
}

/// A field's material is not another field's.
#[test]
fn test_the_material_differs_between_fields() {
    assert_ne!(material(Field::Ikm, 32), material(Field::Salt, 32));
    assert_ne!(material(Field::Salt, 32), material(Field::Info, 32));
}

/// Every row of the file has a length this walk reaches, and the other way
/// round.
///
/// The rows are matched to the walk by position, so a file whose lengths are not
/// the ones being walked would be compared row by row against the wrong
/// derivations. It is also what says the sweep below is not an empty loop: an
/// equality nobody reaches passes without comparing anything.
#[test]
fn test_the_file_covers_the_lengths_the_walk_reaches() {
    let published: Vec<usize> = published().iter().map(|(length, _)| *length).collect();
    let walked: Vec<usize> = INFO_LENGTHS.collect();

    assert_eq!(published, walked, "the file and the walk disagree");
}

// === === === === === === === === === ===
// What libsodium answered
// === === === === === === === === === ===

/// How many ways the walk is split, so that the cores are.
///
/// Eight, against two backends, is one test per core on a machine with sixteen.
/// The work is the same; what changes is that it stops being one process.
///
/// **This has to equal how many values `shard` is given below**, and nothing
/// makes it. Fewer values than this and the rows in the shards nobody was given
/// are never walked, and the ones that are walked still agree, so the suite
/// stays green over a corpus it stopped reading. The `assert!` in the body
/// catches the other direction only.
const SHARDS: usize = 8;

/// Nothing is asserted about an answer here that the corpora do not already
/// pin; what is asserted is that a quarter of a million lengths agree with
/// libsodium.
///
/// Each case takes every `SHARDS`th row, so the union of them is the file and
/// no row is walked twice.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_every_length_agrees_with_libsodium(
    #[case] backend: Backend,
    #[values(0, 1, 2, 3, 4, 5, 6, 7)] shard: usize,
) {
    assert!(shard < SHARDS, "a shard the walk is not split into");

    for (at, (info_len, expected)) in published().into_iter().enumerate() {
        if at % SHARDS != shard {
            continue;
        }

        let info = material(Field::Info, info_len);

        assert_eq!(
            hex(&row(backend, &info)),
            expected,
            "the row libsodium answered for an info of {info_len} bytes"
        );
    }
}
