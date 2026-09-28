// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_asm::Backend;
use rstest::rstest;

use crate::xchacha20::XChaCha20;

use crate::tests::support::vectors;

// ============================================================================
// xor
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_xor_returns_the_published_ciphertext_at_the_counter_named(#[case] backend: Backend) {
    let mut data = vectors::DHOLE.to_vec();

    XChaCha20::new().xor(
        backend,
        &vectors::hex(vectors::XKEY),
        &vectors::hex(vectors::XNONCE),
        1,
        &mut data,
    );

    assert_eq!(data, vectors::hex::<304>(vectors::XCIPHERTEXT[1]));
}
