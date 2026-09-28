// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_aead_core::consts::chacha::KEY_SIZE;
use redoubt_asm::Backend;
use rstest::rstest;

use crate::hchacha20::HChaCha20;

use crate::tests::support::vectors;

// ============================================================================
// subkey
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_subkey_returns_the_published_subkey(#[case] backend: Backend) {
    let key = core::array::from_fn(|at| at as u8);
    let nonce = vectors::hex(vectors::HNONCE);
    let mut out = [0xa5; KEY_SIZE];

    HChaCha20::new().subkey(backend, &mut out, &key, &nonce);

    assert_eq!(out, vectors::hex::<KEY_SIZE>(vectors::SUBKEY));
}
