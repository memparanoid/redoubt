// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each entry point answers, asked of every backend the target has.
//!
//! One file per primitive, and the rounds here because they are what all three
//! are built on.

mod chacha20;
mod hchacha20;
mod xchacha20;

use proptest::prelude::*;
use rstest::rstest;

use redoubt_asm::Backend;

use crate::backend::rounds;

use crate::tests::support::{oracle, vectors};

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
