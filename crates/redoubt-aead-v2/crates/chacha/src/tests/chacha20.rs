// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::vec::Vec;

use rstest::rstest;

use redoubt_aead_v2_core::Backend;
use redoubt_aead_v2_core::consts::chacha::{BLOCK_SIZE, KEY_SIZE, NONCE_SIZE};

use crate::chacha20::ChaCha20;

use super::support::vectors::{VECTORS, Vector};

// === === === === === === === === === ===
// xor
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_returns_the_published_ciphertext(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);

    for Vector {
        from,
        key,
        nonce,
        counter,
        plaintext,
        ciphertext,
    } in VECTORS
    {
        let mut data: Vec<u8> = plaintext.to_vec();
        cipher.xor(key, nonce, *counter, &mut data);

        assert_eq!(&data, ciphertext, "{from}");
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_returns_the_plaintext_when_it_is_run_twice(#[case] backend: Backend) {
    let cipher = ChaCha20::with_backend(backend);
    let key = [0x42; KEY_SIZE];
    let nonce = [0x17; NONCE_SIZE];

    // Over a block boundary and past it, so the counter has to move and the
    // last block has to be a partial one.
    let plaintext: Vec<u8> = (0..BLOCK_SIZE * 2 + 7).map(|at| at as u8).collect();
    let mut data = plaintext.clone();

    cipher.xor(&key, &nonce, 0, &mut data);
    assert_ne!(data, plaintext);

    cipher.xor(&key, &nonce, 0, &mut data);
    assert_eq!(data, plaintext);
}

// === === === === === === === === === ===
// xor_bernstein
// === === === === === === === === === ===

// === === === === === === === === === ===
// with_backend
// === === === === === === === === === ===
