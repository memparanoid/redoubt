// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_asm::Backend;
use rstest::rstest;

use crate::eq::{constant_time_eq, constant_time_eq_using};

const TAG_SIZE: usize = 16;

// ============================================================================
// constant_time_eq
// ============================================================================

#[test]
fn test_constant_time_eq_answers_from_the_default_backend() {
    let a = [0x5au8; TAG_SIZE];
    let mut b = a;

    assert!(constant_time_eq(&a, &b));

    b[TAG_SIZE - 1] ^= 1;

    assert!(!constant_time_eq(&a, &b));
}

// ============================================================================
// constant_time_eq_using
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_constant_time_eq_using_answers_for_equal_runs_and_for_different_ones(
    #[case] backend: Backend,
) {
    let a = [0x5au8; TAG_SIZE];
    let mut b = a;

    assert!(constant_time_eq_using(backend, &a, &b));

    b[0] ^= 1;

    assert!(!constant_time_eq_using(backend, &a, &b));
}
