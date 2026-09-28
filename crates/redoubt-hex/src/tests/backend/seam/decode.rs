// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That both backends read what the standard library's parsing reads, and
//! refuse what it refuses.

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use redoubt_asm::Backend;
use rstest::rstest;

use crate::backend::hex_to_bytes;

/// Both backends, for the proptests, which take no cases of their own.
const BACKENDS: [Backend; 2] = [Backend::Rust, Backend::Auto];

/// What the digits spell by `u8::from_str_radix`, or nothing when one of them
/// is not a hex digit. The sign it would accept is not a digit here.
fn parsed(digits: &[u8]) -> Option<Vec<u8>> {
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }

    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = core::str::from_utf8(pair).ok()?;

            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

fn agrees(backend: Backend, digits: &[u8]) {
    let mut bytes = vec![0xA5_u8; digits.len() / 2];

    // SAFETY: every caller hands an even count, and `bytes` is half as long.
    let accepted = unsafe { hex_to_bytes(backend, digits, &mut bytes) };

    match parsed(digits) {
        Some(expected) => {
            assert!(accepted, "{backend:?}: refused {digits:02x?}");
            assert_eq!(bytes, expected, "{backend:?}: {digits:02x?}");
        }
        None => {
            assert!(!accepted, "{backend:?}: accepted {digits:02x?}");
            assert!(
                bytes.iter().all(|byte| *byte == 0),
                "{backend:?}: refused {digits:02x?} and left {bytes:02x?}"
            );
        }
    }
}

// ============================================================================
// hex_to_bytes
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hex_to_bytes_reads_as_parsing_on_nothing(#[case] backend: Backend) {
    agrees(backend, &[]);
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hex_to_bytes_reads_as_parsing_on_every_pair_of_bytes(#[case] backend: Backend) {
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            agrees(backend, &[first, second]);
        }
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hex_to_bytes_refuses_one_character_that_is_not_a_digit_at_every_position(
    #[case] backend: Backend,
) {
    for len in (2..=64).step_by(2) {
        for at in 0..len {
            let mut digits: Vec<u8> = (0..len)
                .map(|at| b"0123456789abcdefABCDEF"[at % 22])
                .collect();

            digits[at] = b'g';

            agrees(backend, &digits);
        }
    }
}

proptest! {
    #[test]
    fn test_hex_to_bytes_reads_as_parsing_on_any_digits(
        digits in proptest::collection::vec(
            prop_oneof![
                prop::sample::select(b"0123456789abcdefABCDEF".to_vec()),
                any::<u8>(),
            ],
            0..256,
        ).prop_map(|mut digits| { digits.truncate(digits.len() & !1); digits }),
    ) {
        for backend in BACKENDS {
            agrees(backend, &digits);
        }
    }
}
