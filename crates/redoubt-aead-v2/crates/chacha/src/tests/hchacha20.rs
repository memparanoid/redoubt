// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use proptest::prelude::*;
use rstest::rstest;

use redoubt_aead_v2_core::Backend;
use redoubt_aead_v2_core::consts::chacha::{HNONCE_SIZE, KEY_SIZE};

use crate::hchacha20::HChaCha20;

use super::support::{oracle, vectors};

// === === === === === === === === === ===
// subkey
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_subkey_returns_the_published_subkey(#[case] backend: Backend) {
    let cipher = HChaCha20::with_backend(backend);
    let key = core::array::from_fn(|at| at as u8);
    let nonce = vectors::hex(vectors::HNONCE);
    let mut out = [0xa5; KEY_SIZE];

    cipher.subkey(&mut out, &key, &nonce);

    assert_eq!(out, vectors::hex::<KEY_SIZE>(vectors::SUBKEY));
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_subkey_overwrites_only_the_output_at_every_alignment(#[case] backend: Backend) {
    let cipher = HChaCha20::with_backend(backend);

    for offset in 0..16 {
        let key_storage: [u8; KEY_SIZE + 16] = core::array::from_fn(|at| at as u8);
        let nonce_storage: [u8; HNONCE_SIZE + 16] = core::array::from_fn(|at| 0x80 + at as u8);
        let key = key_storage[offset..offset + KEY_SIZE].try_into().unwrap();
        let nonce = nonce_storage[offset..offset + HNONCE_SIZE]
            .try_into()
            .unwrap();
        let expected = oracle::subkey(key, nonce);

        for fill in [0, 0xa5, 0xff] {
            let mut storage = [fill; KEY_SIZE + 32];
            cipher.subkey(
                (&mut storage[offset..offset + KEY_SIZE])
                    .try_into()
                    .unwrap(),
                key,
                nonce,
            );

            assert_eq!(
                &storage[offset..offset + KEY_SIZE],
                expected,
                "offset {offset}"
            );
            assert!(storage[..offset].iter().all(|&byte| byte == fill));
            assert!(
                storage[offset + KEY_SIZE..]
                    .iter()
                    .all(|&byte| byte == fill)
            );
        }

        assert_eq!(key_storage, core::array::from_fn(|at| at as u8));
        assert_eq!(nonce_storage, core::array::from_fn(|at| 0x80 + at as u8));
    }
}

proptest! {
    #[test]
    fn test_subkey_returns_what_the_oracle_returns(
        key: [u8; KEY_SIZE],
        nonce: [u8; HNONCE_SIZE],
    ) {
        let expected = oracle::subkey(&key, &nonce);

        for backend in [Backend::Rust, Backend::Auto] {
            let mut out = [0xa5; KEY_SIZE];
            HChaCha20::with_backend(backend).subkey(&mut out, &key, &nonce);

            prop_assert_eq!(out, expected, "{:?}", backend);
        }
    }
}

// === === === === === === === === === ===
// with_backend
// === === === === === === === === === ===

#[test]
fn test_with_backend_defaults_to_auto() {
    assert_eq!(HChaCha20::new(), HChaCha20::with_backend(Backend::Auto));
    assert_eq!(HChaCha20::default(), HChaCha20::new());
    assert_ne!(HChaCha20::with_backend(Backend::Rust), HChaCha20::new());
}
