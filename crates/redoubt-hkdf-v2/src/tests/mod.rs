// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! One file here for each file there, and the same shape of directory around
//! them.

mod backend;
mod hkdf;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

/// Bytes as the lowercase hex every published answer is written in.
pub(crate) fn hex(of: &[u8]) -> String {
    let mut said = String::with_capacity(of.len() * 2);

    for byte in of {
        write!(said, "{byte:02x}")
            .expect("Infallible: a String never refuses what is written to it");
    }

    said
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
