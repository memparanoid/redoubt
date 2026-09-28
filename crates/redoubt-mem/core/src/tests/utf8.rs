// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::string::String;

use proptest::prelude::*;
use redoubt_asm::Backend;
use rstest::rstest;

use crate::is_utf8;
use crate::utf8::is_utf8_using;

// ============================================================================
// is_utf8
// ============================================================================

proptest! {
    #[test]
    fn test_is_utf8_returns_true_for_any_text(text in any::<String>()) {
        prop_assert!(is_utf8(text.as_bytes()));
    }

    #[test]
    fn test_is_utf8_returns_false_for_any_text_holding_a_byte_utf8_never_uses(
        text in any::<String>(),
        at in any::<prop::sample::Index>(),
        byte in prop_oneof![Just(0xC0_u8), Just(0xC1), 0xF5_u8..=0xFF],
    ) {
        let mut bytes = text.into_bytes();

        bytes.insert(at.index(bytes.len() + 1), byte);

        prop_assert!(!is_utf8(&bytes));
    }
}

// ============================================================================
// is_utf8_using
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_is_utf8_using_answers_for_text_and_for_what_is_not(#[case] backend: Backend) {
    let text = "a\u{e9}\u{20ac}\u{1f600}z".as_bytes();

    assert!(is_utf8_using(backend, text));
    assert!(!is_utf8_using(backend, &text[..text.len() - 2]));
}
