// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use rstest::rstest;

use redoubt_zero_core::{FastZeroizable, ZeroizationProbe, ZeroizeOnDropSentinel};
use redoubt_zero_derive::RedoubtZero;

#[derive(RedoubtZero, Debug, PartialEq)]
enum Held<'a> {
    Empty,
    Bytes([u8; 16]),
    Keyed {
        key: [u8; 32],
        #[fast_zeroize(skip)]
        label: &'a str,
        id: u64,
    },
}

#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
enum Guarded {
    Watched(ZeroizeOnDropSentinel),
}

#[derive(RedoubtZero)]
enum Unguarded {
    Watched(ZeroizeOnDropSentinel),
}

// ============================================================================
// fast_zeroize
// ============================================================================

#[rstest]
#[case::empty(Held::Empty, Held::Empty)]
#[case::bytes(Held::Bytes([0x5A; 16]), Held::Bytes([0; 16]))]
#[case::keyed(
    Held::Keyed { key: [0x6B; 32], label: "kept", id: 7 },
    Held::Keyed { key: [0; 32], label: "kept", id: 0 },
)]
fn test_fast_zeroize_empties_the_live_variant_and_keeps_what_is_skipped(
    #[case] mut held: Held<'static>,
    #[case] emptied: Held<'static>,
) {
    held.fast_zeroize();

    assert_eq!(held, emptied);
}

// ============================================================================
// is_zeroized
// ============================================================================

#[rstest]
#[case::bytes(Held::Bytes([0x5A; 16]))]
#[case::keyed(Held::Keyed { key: [0x6B; 32], label: "kept", id: 7 })]
fn test_is_zeroized_returns_false_while_the_live_variant_holds_data(#[case] held: Held<'static>) {
    assert!(!held.is_zeroized());
}

#[rstest]
#[case::empty(Held::Empty)]
#[case::bytes(Held::Bytes([0; 16]))]
#[case::keyed(Held::Keyed { key: [0; 32], label: "kept", id: 0 })]
fn test_is_zeroized_returns_true_once_the_live_variant_is_empty(#[case] held: Held<'static>) {
    assert!(held.is_zeroized());
}

// ============================================================================
// Drop
// ============================================================================

#[test]
fn test_drop_zeroizes_the_live_variant() {
    let sentinel = ZeroizeOnDropSentinel::default();
    let guarded = Guarded::Watched(sentinel.clone());

    drop(guarded);

    assert!(sentinel.is_zeroized());
}

#[test]
fn test_drop_without_the_attribute_leaves_the_live_variant() {
    let sentinel = ZeroizeOnDropSentinel::default();
    let unguarded = Unguarded::Watched(sentinel.clone());

    drop(unguarded);

    assert!(!sentinel.is_zeroized());
}
