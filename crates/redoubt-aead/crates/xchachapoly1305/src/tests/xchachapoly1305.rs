// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the construction holds, and what it leaves the caller holding.

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use rstest::rstest;

use redoubt_aead_core::consts::chacha::{KEY_SIZE, XNONCE_SIZE};
use redoubt_aead_core::consts::poly1305::TAG_SIZE;
use redoubt_aead_core::{AeadCoreError, AeadDecrypt, AeadEncrypt};
use redoubt_alloc::RedoubtVec;
use redoubt_asm::Backend;
use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::xchachapoly1305::XChaCha20Poly1305;

const KEY: [u8; KEY_SIZE] = [0x42; KEY_SIZE];
const NONCE: [u8; XNONCE_SIZE] = [0x17; XNONCE_SIZE];

// === === === === === === === === === ===
// XChaCha20Poly1305
// === === === === === === === === === ===

/// What it holds in a build that ships is where its operations go, and there is
/// nothing there to empty. What these two work on is the cipher's own marker,
/// so that the wipe and the drop are exercised against something rather than
/// against a type that would pass either way.
#[test]
fn test_xchachapoly1305_is_zeroizable() {
    let mut aead = XChaCha20Poly1305::new();

    aead.unzeroize();
    assert!(!aead.is_zeroized());

    aead.fast_zeroize();

    // Assert zeroization!
    assert!(aead.is_zeroized());
}

#[test]
fn test_xchachapoly1305_zeroizes_on_drop() {
    let mut aead = XChaCha20Poly1305::new();

    aead.unzeroize();
    assert!(!aead.is_zeroized());

    // Assert zeroization!
    aead.assert_zeroize_on_drop();
}

// === === === === === === === === === ===
// decrypt
// === === === === === === === === === ===

/// A tag that does not match leaves the caller's buffer empty.
///
/// What is in it at that moment is a keystream laid over bytes nobody
/// authenticated, which is to say what an attacker chose to send. A caller that
/// ignores the error and reads on reads that, and the trait says this is where
/// it stops being possible.
///
/// Every length is asked, because the wipe is over a slice and a wipe that
/// covered whole blocks only would leave the tail of anything that does not end
/// on one.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_decrypt_empties_the_buffer_when_the_tag_does_not_match(#[case] backend: Backend) {
    let mut aead = XChaCha20Poly1305::with_backend(backend);

    for length in [1usize, 15, 16, 17, 63, 64, 65, 1024] {
        let mut data = vec![0xAB_u8; length];
        let mut tag = [0u8; TAG_SIZE];

        aead.encrypt(&KEY, &NONCE, b"", &mut data, &mut tag);

        // What makes the reading below mean anything: the buffer has to be
        // holding something on the way in, or an emptiness afterwards says only
        // that it was empty already.
        assert!(
            !data.is_zeroized(),
            "the ciphertext to be refused is already empty, {length} bytes in"
        );

        tag[0] ^= 1;

        let refused = aead.decrypt(&KEY, &NONCE, b"", &mut data, &tag);

        assert_eq!(
            refused,
            Err(AeadCoreError::AuthenticationFailed),
            "a turned-over tag was taken, {length} bytes in"
        );

        // Assert zeroization!
        assert!(
            data.is_zeroized(),
            "the buffer still holds what arrived, {length} bytes in"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn test_decrypt_refuses_a_tag_with_any_bit_turned_over(
        key: [u8; KEY_SIZE],
        nonce: [u8; XNONCE_SIZE],
        aad in proptest::collection::vec(any::<u8>(), 0..=300),
        plaintext in proptest::collection::vec(any::<u8>(), 0..=1024),
        at: usize,
        bit in 0..8_u8,
    ) {
        for backend in [Backend::Rust, Backend::Auto] {
            let mut said = plaintext.clone();
            let mut data = RedoubtVec::default();
            data.replace_from_mut_slice(&mut said);

            let mut aead = XChaCha20Poly1305::with_backend(backend);
            let mut tag = [0u8; TAG_SIZE];

            aead.encrypt(&key, &nonce, &aad, &mut data, &mut tag);

            tag[at % TAG_SIZE] ^= 1 << bit;

            let refused = aead.decrypt(&key, &nonce, &aad, &mut data, &tag);

            prop_assert_eq!(refused, Err(AeadCoreError::AuthenticationFailed));

            // Assert zeroization!
            prop_assert!(data.is_zeroized());
        }
    }
}

/// And the other way round, which is what says the wipe above is the refusal
/// and not something that happens either way.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_decrypt_leaves_the_plaintext_when_the_tag_matches(#[case] backend: Backend) {
    let mut aead = XChaCha20Poly1305::with_backend(backend);

    for length in [1usize, 15, 16, 17, 63, 64, 65, 1024] {
        let plaintext = vec![0xAB_u8; length];
        let mut data = plaintext.clone();
        let mut tag = [0u8; TAG_SIZE];

        aead.encrypt(&KEY, &NONCE, b"", &mut data, &mut tag);
        aead.decrypt(&KEY, &NONCE, b"", &mut data, &tag)
            .expect("Infallible: the tag is the one encrypt just wrote");

        assert_eq!(data, plaintext, "{length} bytes in");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn test_decrypt_returns_what_encrypt_was_given(
        key: [u8; KEY_SIZE],
        nonce: [u8; XNONCE_SIZE],
        aad in proptest::collection::vec(any::<u8>(), 0..=300),
        plaintext in proptest::collection::vec(any::<u8>(), 0..=1024),
    ) {
        for backend in [Backend::Rust, Backend::Auto] {
            let mut aead = XChaCha20Poly1305::with_backend(backend);
            let mut data: Vec<u8> = plaintext.clone();
            let mut tag = [0u8; TAG_SIZE];

            aead.encrypt(&key, &nonce, &aad, &mut data, &mut tag);

            let opened = aead.decrypt(&key, &nonce, &aad, &mut data, &tag);

            prop_assert_eq!(opened, Ok(()));
            prop_assert_eq!(&data, &plaintext);
        }
    }
}
