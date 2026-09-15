// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::vec::Vec;

use proptest::prelude::*;
use rstest::rstest;

use redoubt_aead_v2_core::Backend;
use redoubt_aead_v2_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};
use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::backend::HAS_ASM;
use crate::poly1305::{Poly1305, tag_with_backend};

use super::support::oracle;
use super::support::vectors::{VECTORS, Vector};

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
// Test helpers
// === === === === === === === === === ===

/// One message through one authenticator, whole.
fn tag_of(backend: Backend, key: &[u8; KEY_SIZE], message: &[u8]) -> [u8; TAG_SIZE] {
    let mut poly = Poly1305::with_backend(backend, key);
    let mut tag = [0u8; TAG_SIZE];

    poly.update(message);
    poly.finalize_mut(&mut tag);

    tag
}

/// The same message, handed over in two pieces split at `at`.
fn tag_of_split(
    backend: Backend,
    key: &[u8; KEY_SIZE],
    message: &[u8],
    at: usize,
) -> [u8; TAG_SIZE] {
    let mut poly = Poly1305::with_backend(backend, key);
    let mut tag = [0u8; TAG_SIZE];
    let (head, rest) = message.split_at(at);

    poly.update(head);
    poly.update(rest);
    poly.finalize_mut(&mut tag);

    tag
}

// === === === === === === === === === ===
// Poly1305
// === === === === === === === === === ===

#[test]
fn test_poly1305_is_zeroizable() {
    let mut poly = Poly1305::new(&[0x11; KEY_SIZE]);

    poly.unzeroize();
    assert!(!poly.is_zeroized());

    poly.fast_zeroize();

    // Assert zeroization!
    assert!(poly.is_zeroized());
}

#[test]
fn test_poly1305_zeroizes_on_drop() {
    let mut poly = Poly1305::new(&[0x11; KEY_SIZE]);

    poly.unzeroize();
    assert!(!poly.is_zeroized());

    // Assert zeroization!
    poly.assert_zeroize_on_drop();
}

#[test]
fn test_poly1305_debug_says_nothing() {
    let poly = Poly1305::new(&[0xab; KEY_SIZE]);

    assert_eq!(std::format!("{poly:?}"), "Poly1305 { [protected] }");
}

// === === === === === === === === === ===
// update
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_update_returns_the_same_tag_at_every_split(#[case] backend: Backend) {
    let key = [0x5e; KEY_SIZE];
    let message: Vec<u8> = (0..70u16).map(|i| i as u8).collect();
    let whole = tag_of(backend, &key, &message);

    for at in 0..=message.len() {
        assert_eq!(
            tag_of_split(backend, &key, &message, at),
            whole,
            "split at {at} of {}",
            message.len()
        );
    }
}

// === === === === === === === === === ===
// update_padded
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_update_padded_returns_the_tag_of_the_message_and_its_zeros(#[case] backend: Backend) {
    let key = [0x91; KEY_SIZE];

    // Nothing owed at 0, 16 and 32; fifteen owed at 1 and 17; one owed at 15
    // and 31. The multiples are what a `% BLOCK_SIZE` written once instead of
    // twice gets wrong, by owing a whole block of zeros that nobody owes.
    for length in [0usize, 1, 15, 16, 17, 31, 32] {
        let message: Vec<u8> = (0..length).map(|i| (i as u8) ^ 0x5a).collect();

        let mut padded = message.clone();
        padded.resize(length.next_multiple_of(BLOCK_SIZE), 0);

        let mut poly = Poly1305::with_backend(backend, &key);
        let mut tag = [0u8; TAG_SIZE];

        poly.update_padded(&message);
        poly.finalize_mut(&mut tag);

        assert_eq!(tag, tag_of(backend, &key, &padded), "{length} bytes in");
    }
}

// === === === === === === === === === ===
// finalize_mut
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_finalize_mut_returns_the_appendix_tag(#[case] backend: Backend) {
    for Vector {
        number,
        asks,
        key,
        message,
        tag: expected,
    } in VECTORS
    {
        assert_eq!(
            &tag_of(backend, key, message),
            expected,
            "RFC 8439 A.3 vector #{number} asks about {asks}"
        );
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_finalize_mut_empties_the_state_it_answered_from(#[case] backend: Backend) {
    // Long enough to leave a tail in the buffer: what an emptying that only
    // reached the accumulator would leave behind is the last block of the
    // message, and a message ending on a boundary would not have one.
    let key = [0x3f; KEY_SIZE];
    let message = b"long enough to leave a tail in the buffer at the end";

    let mut poly = Poly1305::with_backend(backend, &key);
    let mut tag = [0u8; TAG_SIZE];

    poly.update(message);
    poly.finalize_mut(&mut tag);

    // Assert zeroization!
    assert!(poly.is_zeroized());
}

// === === === === === === === === === ===
// tag_with_backend
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_tag_with_backend_returns_the_appendix_tag(#[case] backend: Backend) {
    for Vector {
        number,
        asks,
        key,
        message,
        tag: expected,
    } in VECTORS
    {
        let mut tag = [0u8; TAG_SIZE];
        tag_with_backend(backend, key, message, &mut tag);

        assert_eq!(
            &tag, expected,
            "RFC 8439 A.3 vector #{number} asks about {asks}"
        );
    }
}

proptest! {
    #[test]
    fn test_tag_with_backend_returns_what_the_oracle_returns(
        key: [u8; KEY_SIZE],
        message in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let expected = oracle::tag(&key, &message);

        let mut rust = [0u8; TAG_SIZE];
        let mut auto = [0u8; TAG_SIZE];

        tag_with_backend(Backend::Rust, &key, &message, &mut rust);
        tag_with_backend(Backend::Auto, &key, &message, &mut auto);

        prop_assert_eq!(rust, expected);
        prop_assert_eq!(auto, expected);
    }
}
