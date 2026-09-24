// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That `is_utf8` answers what the standard library's check answers, which is
//! the oracle: an implementation from outside this workspace.

use std::string::String;
use std::vec::Vec;

use proptest::prelude::*;

use crate::is_utf8;

/// Each byte a continuation may be tested against: the edges of 80..BF, the
/// edges of the narrowed ranges after E0, ED, F0 and F4, and a byte either
/// side of all of them.
const EDGES: [u8; 10] = [0x00, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xFF];

fn agrees(bytes: &[u8]) {
    assert_eq!(
        is_utf8(bytes),
        core::str::from_utf8(bytes).is_ok(),
        "{bytes:02x?}"
    );
}

/// ASCII, then each of the three wider widths, so a run of it crosses every
/// kind of boundary.
fn text() -> Vec<u8> {
    "a\u{e9}\u{20ac}\u{1f600}z".repeat(16).into_bytes()
}

// ============================================================================
// is_utf8
// ============================================================================

#[test]
fn test_is_utf8_answers_as_the_standard_library_on_nothing() {
    agrees(&[]);
}

#[test]
fn test_is_utf8_answers_as_the_standard_library_on_every_byte() {
    for first in 0..=u8::MAX {
        agrees(&[first]);
    }
}

#[test]
fn test_is_utf8_answers_as_the_standard_library_on_every_pair() {
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            agrees(&[first, second]);
        }
    }
}

#[test]
fn test_is_utf8_answers_as_the_standard_library_on_every_triple() {
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            for third in 0..=u8::MAX {
                agrees(&[first, second, third]);
            }
        }
    }
}

#[test]
fn test_is_utf8_answers_as_the_standard_library_on_every_four_byte_lead() {
    for first in 0xF0..=u8::MAX {
        for second in 0..=u8::MAX {
            for third in EDGES {
                for fourth in EDGES {
                    agrees(&[first, second, third, fourth]);
                }
            }
        }
    }
}

#[test]
fn test_is_utf8_answers_as_the_standard_library_on_text_cut_at_every_length() {
    let text = text();

    for len in 0..=text.len() {
        agrees(&text[..len]);
    }
}

#[test]
fn test_is_utf8_answers_as_the_standard_library_on_text_broken_at_every_byte() {
    for at in 0..text().len() {
        for broken in [0x80, 0xC0, 0xED, 0xF5, 0xFF] {
            let mut text = text();

            text[at] = broken;

            agrees(&text);
        }
    }
}

proptest! {
    #[test]
    fn test_is_utf8_answers_as_the_standard_library_on_any_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        agrees(&bytes);
    }

    #[test]
    fn test_is_utf8_answers_as_the_standard_library_on_any_text_with_one_byte_changed(
        text in any::<String>(),
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        let mut bytes = text.into_bytes();

        agrees(&bytes);

        if !bytes.is_empty() {
            let at = at.index(bytes.len());

            bytes[at] = byte;

            agrees(&bytes);
        }
    }
}
