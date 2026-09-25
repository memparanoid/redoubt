// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! One file here for each file there, and the same shape of directory around
//! them.

mod support;

#[cfg(target_os = "linux")]
mod forensics;

mod backend;
mod hkdf;
mod libsodium;
mod rfc;
mod sha256;
mod wycheproof;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

/// The files as NIST published them, read from here so that the path to them
/// is written once and a file that moves breaks in one place.
pub(crate) const SHORT_MSG: &str = include_str!("../../vectors/SHA256ShortMsg.rsp");
pub(crate) const LONG_MSG: &str = include_str!("../../vectors/SHA256LongMsg.rsp");
pub(crate) const MONTE: &str = include_str!("../../vectors/SHA256Monte.rsp");

/// One digest per info length, generated from libsodium by the script beside
/// it, read from here for the same reason the three above are.
pub(crate) const SODIUM_DIGESTS: &str = include_str!("../../vectors/hkdf_sha256_digests.txt");

/// How many messages each of them says it has, so a file that arrived
/// truncated is a failure and not a shorter run that passes.
pub(crate) const SHORT_MSG_COUNT: usize = 65;
pub(crate) const LONG_MSG_COUNT: usize = 64;
pub(crate) const MONTE_COUNT: usize = 100;
pub(crate) const MD_COUNT: usize = 131;

/// How many digests the Monte Carlo takes between one checkpoint and the next.
pub(crate) const CHAINED: usize = 1_000;

/// Bytes as the lowercase hex every published answer is written in.
pub(crate) fn hex(of: &[u8]) -> String {
    let mut said = String::with_capacity(of.len() * 2);

    for byte in of {
        write!(said, "{byte:02x}")
            .expect("Infallible: a String never refuses what is written to it");
    }

    said
}

/// The value of every `Name = value` line with that name.
///
/// The names that matter are distinct in their first characters, so a prefix is
/// enough to tell them apart and the header lines match none of them.
pub(crate) fn field<'a>(said: &'a str, name: &str) -> Vec<&'a str> {
    said.lines()
        .filter_map(|line| line.trim().strip_prefix(name))
        .filter_map(|rest| rest.trim_start().strip_prefix('='))
        .map(str::trim)
        .collect()
}

/// Every message of one of the two message files with the answer published for
/// it.
pub(crate) fn messages(file: &str, counted: usize) -> Vec<(Vec<u8>, String)> {
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

/// The same read back.
pub(crate) fn from_hex(said: &str) -> Vec<u8> {
    assert!(said.len().is_multiple_of(2), "hex comes in pairs: {said}");

    said.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).expect("hex is ascii");

            u8::from_str_radix(pair, 16).expect("a pair of hex digits")
        })
        .collect()
}
