// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use proptest::prelude::*;
use rstest::rstest;

use redoubt_aead_v2_core::Backend;

use crate::backend::{HAS_ASM, rounds};

use super::support::{oracle, vectors};

/// The precondition every case below rests on, which is why it is first.
///
/// The two backends are the same code where the target has no assembly, and a
/// pair of cases that found them agreeing there would have proved nothing
/// about either — while reading as though it had proved it twice.
#[test]
#[expect(
    clippy::assertions_on_constants,
    reason = "a constant is what it asks about: whether this build has the assembly at all"
)]
fn test_this_target_has_the_assembly() {
    assert!(
        HAS_ASM,
        "the cases below name two backends and this target has one"
    );
}

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
