// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use proptest::prelude::*;
use rstest::rstest;

use redoubt_aead_v2_core::Backend;

use crate::backend::rounds;

use super::support::{oracle, vectors};

// === === === === === === === === === ===
// rounds
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_rounds_returns_the_published_intermediate_state(#[case] backend: Backend) {
    let mut state = vectors::INITIAL;

    rounds(backend, &mut state);

    assert_eq!(state, vectors::PERMUTED);
}

proptest! {
    #[test]
    fn test_rounds_returns_what_the_oracle_returns(input: [u32; 16]) {
        let expected = oracle::rounds(input);

        for backend in [Backend::Rust, Backend::Auto] {
            let mut state = input;
            rounds(backend, &mut state);

            prop_assert_eq!(state, expected, "{:?}", backend);
        }
    }
}
