// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_aead_core::consts::chacha::{BERNSTEIN_NONCE_SIZE, BLOCK_SIZE, KEY_SIZE};
use redoubt_asm::Backend;
use rstest::rstest;

use crate::chacha20::ChaCha20;

use crate::tests::support::vectors;

// ============================================================================
// xor
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_returns_the_published_ciphertext(#[case] backend: Backend) {
    let vector = vectors::SUNSCREEN;
    let mut data = vector.plaintext.to_vec();

    ChaCha20::new().xor(
        backend,
        &vector.key,
        &vector.nonce,
        vector.counter,
        &mut data,
    );

    assert_eq!(data, vector.ciphertext);
}

// ============================================================================
// xor_bernstein
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_bernstein_returns_the_published_block(#[case] backend: Backend) {
    let mut data = [0_u8; BLOCK_SIZE];

    ChaCha20::new().xor_bernstein(
        backend,
        &[0; KEY_SIZE],
        &[0; BERNSTEIN_NONCE_SIZE],
        0,
        &mut data,
    );

    assert_eq!(data, vectors::hex::<BLOCK_SIZE>(vectors::ZERO_BLOCK));
}
