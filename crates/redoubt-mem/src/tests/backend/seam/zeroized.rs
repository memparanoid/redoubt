// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That both backends answer what every byte compared with zero answers.

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use redoubt_asm::Backend;
use rstest::rstest;

use crate::zeroized::is_zeroized_with_backend;

/// Both backends, for the proptests, which take no cases of their own.
const BACKENDS: [Backend; 2] = [Backend::Rust, Backend::Auto];

fn agrees(backend: Backend, bytes: &[u8]) {
    assert_eq!(
        is_zeroized_with_backend(backend, bytes),
        bytes.iter().all(|byte| *byte == 0),
        "{backend:?}: {bytes:02x?}"
    );
}

// ============================================================================
// is_zeroized
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_is_zeroized_answers_as_the_comparison_on_nothing(#[case] backend: Backend) {
    agrees(backend, &[]);
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_is_zeroized_answers_as_the_comparison_on_every_byte(#[case] backend: Backend) {
    for byte in 0..=u8::MAX {
        agrees(backend, &[byte]);
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_is_zeroized_answers_as_the_comparison_with_one_byte_set_at_every_position(
    #[case] backend: Backend,
) {
    for len in 1..=64 {
        for at in 0..len {
            let mut bytes: Vec<u8> = vec![0; len];

            bytes[at] = 0x80;

            agrees(backend, &bytes);
        }
    }
}

proptest! {
    #[test]
    fn test_is_zeroized_answers_as_the_comparison_on_any_bytes(
        bytes in proptest::collection::vec(prop_oneof![Just(0_u8), any::<u8>()], 0..256),
    ) {
        for backend in BACKENDS {
            agrees(backend, &bytes);
        }
    }
}
