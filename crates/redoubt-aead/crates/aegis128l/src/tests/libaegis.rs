// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::string::String;
use std::vec::Vec;

use core::fmt::Write;

use rstest::rstest;

use redoubt_aead_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use redoubt_aead_core::{AeadDecrypt, AeadEncrypt};
use redoubt_hkdf::sha256;

use crate::aegis128l::Aegis128L;

const DIGESTS: &str = include_str!("../../vectors/aegis128l_digests.txt");

const DIGEST_SIZE: usize = 32;

fn msg_lengths() -> Vec<usize> {
    (0..248)
        .chain([1024, 4095, 4096, 4097, 16384, 65535, 65536, 65537])
        .collect()
}

fn aad_lengths() -> Vec<usize> {
    (0..56)
        .chain([127, 128, 129, 255, 256, 257, 1024, 4096])
        .collect()
}

const SAMPLES: usize = 2;

#[derive(Clone, Copy)]
enum Field {
    Key,
    Nonce,
    Aad,
    Msg,
}

impl Field {
    const ALL: [Self; 4] = [Self::Key, Self::Nonce, Self::Aad, Self::Msg];

    const fn said(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Nonce => "nonce",
            Self::Aad => "aad",
            Self::Msg => "msg",
        }
    }
}

fn hex(of: &[u8]) -> String {
    let mut said = String::with_capacity(of.len() * 2);

    for byte in of {
        write!(said, "{byte:02x}")
            .expect("Infallible: a String never refuses what is written to it");
    }

    said
}

fn field<'a>(said: &'a str, name: &str) -> Vec<&'a str> {
    said.lines()
        .filter_map(|line| line.trim().strip_prefix(name))
        .filter_map(|rest| rest.trim_start().strip_prefix('='))
        .map(str::trim)
        .collect()
}

fn listed(name: &str) -> Vec<usize> {
    let lines = field(DIGESTS, name);

    assert_eq!(lines.len(), 1, "the header says {name} once");

    lines[0]
        .split(',')
        .map(|length| length.parse().expect("a length is a number"))
        .collect()
}

fn seed(field: Field) -> [u8; DIGEST_SIZE] {
    let mut said = Vec::from(b"redoubt-aegis128l corpus ".as_slice());
    said.extend_from_slice(field.said().as_bytes());

    let mut out = [0_u8; DIGEST_SIZE];
    sha256(&said, &mut out);

    out
}

fn material(field: Field, length: usize, msg_len: usize, aad_len: usize, sample: usize) -> Vec<u8> {
    let seed = seed(field);
    let mut said = Vec::with_capacity(length + DIGEST_SIZE);
    let mut counter = 0_u32;

    while said.len() < length {
        let mut block = Vec::with_capacity(DIGEST_SIZE + 20);
        block.extend_from_slice(&seed);
        block.extend_from_slice(&(length as u32).to_be_bytes());
        block.extend_from_slice(&(msg_len as u32).to_be_bytes());
        block.extend_from_slice(&(aad_len as u32).to_be_bytes());
        block.extend_from_slice(&(sample as u32).to_be_bytes());
        block.extend_from_slice(&counter.to_be_bytes());

        let mut digest = [0_u8; DIGEST_SIZE];
        sha256(&block, &mut digest);

        said.extend_from_slice(&digest);
        counter += 1;
    }

    said.truncate(length);

    said
}

fn published() -> Vec<(usize, &'static str)> {
    let lengths = field(DIGESTS, "Msg");
    let digests = field(DIGESTS, "MD");

    assert_eq!(lengths.len(), digests.len(), "a row has no answer");

    lengths
        .iter()
        .zip(&digests)
        .map(|(length, digest)| {
            (
                length.parse().expect("a message length is a number"),
                *digest,
            )
        })
        .collect()
}

fn row(msg_len: usize) -> String {
    let mut said = Vec::new();

    for aad_len in aad_lengths() {
        for sample in 0..SAMPLES {
            let key: [u8; KEY_SIZE] = material(Field::Key, KEY_SIZE, msg_len, aad_len, sample)
                .try_into()
                .expect("Infallible: material returns exactly the length it is asked for");
            let nonce: [u8; NONCE_SIZE] =
                material(Field::Nonce, NONCE_SIZE, msg_len, aad_len, sample)
                    .try_into()
                    .expect("Infallible: material returns exactly the length it is asked for");
            let aad = material(Field::Aad, aad_len, msg_len, aad_len, sample);
            let msg = material(Field::Msg, msg_len, msg_len, aad_len, sample);

            let mut aead = Aegis128L::new();
            let mut data = msg.clone();
            let mut tag = [0_u8; TAG_SIZE];

            aead.encrypt(&key, &nonce, &aad, &mut data, &mut tag);

            said.extend_from_slice(&data);
            said.extend_from_slice(&tag);

            aead.decrypt(&key, &nonce, &aad, &mut data, &tag)
                .expect("Infallible: it was just encrypted under the same key, nonce and aad");

            assert_eq!(
                data, msg,
                "msg {msg_len}, aad {aad_len}, sample {sample} came back different"
            );
        }
    }

    let mut digest = [0_u8; DIGEST_SIZE];
    sha256(&said, &mut digest);

    hex(&digest)
}

// === === === === === === === === === ===
// What both sides have to agree on
// === === === === === === === === === ===

#[test]
fn test_the_message_lengths_are_the_ones_the_file_was_generated_from() {
    assert_eq!(listed("MsgLengths"), msg_lengths());
}

#[test]
fn test_the_aad_lengths_are_the_ones_the_file_was_generated_from() {
    assert_eq!(listed("AadLengths"), aad_lengths());
}

#[test]
fn test_the_samples_are_the_ones_the_file_was_generated_from() {
    assert_eq!(listed("Samples"), [SAMPLES]);
}

#[test]
fn test_the_seeds_are_the_ones_the_file_was_generated_from() {
    for field in Field::ALL {
        let name = std::format!("Seed {}", field.said());
        let published = self::field(DIGESTS, &name);

        assert_eq!(published.len(), 1, "the header says {name} once");
        assert_eq!(hex(&seed(field)), published[0], "{name}");
    }
}

#[test]
fn test_a_length_does_not_prefix_a_longer_one() {
    let short = material(Field::Msg, 32, 0, 0, 0);
    let long = material(Field::Msg, 64, 0, 0, 0);

    assert_ne!(short[..], long[..32], "the length is not in the derivation");
}

#[test]
fn test_the_material_differs_between_fields() {
    assert_ne!(
        material(Field::Key, 32, 1, 1, 0),
        material(Field::Nonce, 32, 1, 1, 0)
    );
    assert_ne!(
        material(Field::Aad, 32, 1, 1, 0),
        material(Field::Msg, 32, 1, 1, 0)
    );
}

#[test]
fn test_the_material_differs_between_cells() {
    assert_ne!(
        material(Field::Key, 32, 1, 2, 0),
        material(Field::Key, 32, 2, 1, 0)
    );
}

#[test]
fn test_the_material_differs_between_samples() {
    assert_ne!(
        material(Field::Key, 32, 1, 1, 0),
        material(Field::Key, 32, 1, 1, 1)
    );
}

#[test]
fn test_the_file_covers_the_lengths_the_walk_reaches() {
    let published: Vec<usize> = published().iter().map(|(length, _)| *length).collect();

    assert_eq!(published, msg_lengths(), "the file and the walk disagree");
}

// === === === === === === === === === ===
// What libaegis answered
// === === === === === === === === === ===

const SHARDS: usize = 8;

#[rstest]
fn test_every_length_agrees_with_libaegis(#[values(0, 1, 2, 3, 4, 5, 6, 7)] shard: usize) {
    assert!(shard < SHARDS, "a shard the walk is not split into");

    for (at, (msg_len, expected)) in published().into_iter().enumerate() {
        if at % SHARDS != shard {
            continue;
        }

        assert_eq!(
            row(msg_len),
            expected,
            "the row libaegis answered for a message of {msg_len} bytes"
        );
    }
}
