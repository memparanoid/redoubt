// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That both backends write what the standard library's formatting writes.

use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use redoubt_asm::Backend;
use rstest::rstest;

use crate::backend::bytes_to_hex;

/// Both backends, for the proptests, which take no cases of their own.
const BACKENDS: [Backend; 2] = [Backend::Rust, Backend::Auto];

fn agrees(backend: Backend, bytes: &[u8]) {
    let mut digits = vec![0_u8; 2 * bytes.len()];

    // SAFETY: `digits` is twice as long as `bytes`.
    unsafe { bytes_to_hex(backend, bytes, &mut digits) };

    let expected: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();

    assert_eq!(digits, expected.as_bytes(), "{backend:?}: {bytes:02x?}");
}

// ============================================================================
// bytes_to_hex
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_bytes_to_hex_writes_as_formatting_on_nothing(#[case] backend: Backend) {
    agrees(backend, &[]);
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_bytes_to_hex_writes_as_formatting_on_every_byte(#[case] backend: Backend) {
    for byte in 0..=u8::MAX {
        agrees(backend, &[byte]);
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_bytes_to_hex_writes_as_formatting_on_every_length(#[case] backend: Backend) {
    let bytes: Vec<u8> = (0..=u8::MAX).rev().collect();

    for of in 0..=bytes.len() {
        agrees(backend, &bytes[..of]);
    }
}

proptest! {
    #[test]
    fn test_bytes_to_hex_writes_as_formatting_on_any_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        for backend in BACKENDS {
            agrees(backend, &bytes);
        }
    }
}
