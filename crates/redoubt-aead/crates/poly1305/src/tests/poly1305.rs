// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::vec::Vec;

use rstest::rstest;

use redoubt_aead_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};
use redoubt_asm::Backend;
use redoubt_zero::ZeroizationProbe;

use crate::tests::support::{keyed, tag_of, tag_of_split};

// ============================================================================
// update
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_update_in_two_pieces_returns_the_tag_of_the_whole(#[case] backend: Backend) {
    let key = [0x5e; KEY_SIZE];
    let message: Vec<u8> = (0..70u16).map(|i| i as u8).collect();

    assert_eq!(
        tag_of_split(backend, &key, &message, 23),
        tag_of(backend, &key, &message)
    );
}

// ============================================================================
// update_padded
// ============================================================================

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

        let mut poly = keyed(backend, &key);
        let mut tag = [0u8; TAG_SIZE];

        poly.update_padded(backend, &message);
        poly.finalize_mut(backend, &mut tag);

        assert_eq!(tag, tag_of(backend, &key, &padded), "{length} bytes in");
    }
}

// ============================================================================
// finalize_mut
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_finalize_mut_empties_the_state_it_answered_from(#[case] backend: Backend) {
    // Long enough to leave a tail in the buffer: what an emptying that only
    // reached the accumulator would leave behind is the last block of the
    // message, and a message ending on a boundary would not have one.
    let key = [0x3f; KEY_SIZE];
    let message = b"long enough to leave a tail in the buffer at the end";

    let mut poly = keyed(backend, &key);
    let mut tag = [0u8; TAG_SIZE];

    poly.update(backend, message);
    poly.finalize_mut(backend, &mut tag);

    // Assert zeroization!
    assert!(poly.is_zeroized());
}
