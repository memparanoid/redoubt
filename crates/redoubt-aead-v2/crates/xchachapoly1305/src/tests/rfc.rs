// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The vector draft-irtf-cfrg-xchacha publishes for this construction.
//!
//! The corpus in `wycheproof` carries this one too — it is the single vector
//! there flagged as coming from a standard. It is transcribed again here for
//! two reasons: the transcription is somebody else's in that file and ours in
//! this one, and the draft publishes the one-time key as well, which the corpus
//! does not. That middle value is the seam between the cipher and the
//! authenticator, and a construction can answer correctly overall while
//! deriving it some other way.
//!
//! The draft prints it twice, as a hex dump in A.1 and contiguously in A.3.1.
//! What is below is A.3.1, and the two agree.

use rstest::rstest;

use redoubt_aead_v2_core::consts::chacha::{KEY_SIZE, XNONCE_SIZE};
use redoubt_aead_v2_core::consts::poly1305::{KEY_SIZE as POLY_KEY_SIZE, TAG_SIZE};
use redoubt_aead_v2_core::{AeadDecrypt, AeadEncrypt, Backend};
use redoubt_chacha::xchacha20::XChaCha20;
use redoubt_util::hex_to_bytes;

use crate::xchachapoly1305::XChaCha20Poly1305;

/// draft-irtf-cfrg-xchacha-03 A.3.1.
#[rustfmt::skip]
mod published {
    pub(super) const KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    pub(super) const NONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
    pub(super) const AAD: &str = "50515253c0c1c2c3c4c5c6c7";
    pub(super) const ONE_TIME_KEY: &str = "7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5";
    pub(super) const PLAINTEXT: &str = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
    pub(super) const CIPHERTEXT: &str = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e";
    pub(super) const TAG: &str = "c0875924c1c7987947deafd8780acf49";
}

/// The key and the nonce at the widths the construction takes.
fn widths() -> ([u8; KEY_SIZE], [u8; XNONCE_SIZE]) {
    let key = hex_to_bytes(published::KEY)
        .try_into()
        .expect("the published key is thirty-two bytes");

    let nonce = hex_to_bytes(published::NONCE)
        .try_into()
        .expect("the published nonce is twenty-four bytes");

    (key, nonce)
}

// === === === === === === === === === ===
// encrypt
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_encrypt_returns_the_published_ciphertext_and_tag(#[case] backend: Backend) {
    let mut aead = XChaCha20Poly1305::with_backend(backend);
    let (key, nonce) = widths();

    let aad = hex_to_bytes(published::AAD);
    let mut data = hex_to_bytes(published::PLAINTEXT);
    let mut tag = [0u8; TAG_SIZE];

    aead.encrypt(&key, &nonce, &aad, &mut data, &mut tag);

    assert_eq!(data, hex_to_bytes(published::CIPHERTEXT), "the ciphertext");
    assert_eq!(tag.to_vec(), hex_to_bytes(published::TAG), "the tag");
}

// === === === === === === === === === ===
// decrypt
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_decrypt_returns_the_published_plaintext(#[case] backend: Backend) {
    let mut aead = XChaCha20Poly1305::with_backend(backend);
    let (key, nonce) = widths();

    let aad = hex_to_bytes(published::AAD);
    let mut data = hex_to_bytes(published::CIPHERTEXT);
    let tag: [u8; TAG_SIZE] = hex_to_bytes(published::TAG)
        .try_into()
        .expect("the published tag is sixteen bytes");

    aead.decrypt(&key, &nonce, &aad, &mut data, &tag)
        .expect("the published vector is one to accept");

    assert_eq!(data, hex_to_bytes(published::PLAINTEXT), "the plaintext");
}

// === === === === === === === === === ===
// The key between the two halves
// === === === === === === === === === ===

/// The authenticator's key is the one the draft publishes.
///
/// Taken through the cipher rather than through this crate, because what
/// derives it here is private — so what this pins is the answer the
/// construction is built on rather than the call it makes. A construction that
/// took the wrong thirty-two bytes and still agreed with the vector above would
/// disagree here.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_the_one_time_key_is_the_published_one(#[case] backend: Backend) {
    let cipher = XChaCha20::with_backend(backend);
    let (key, nonce) = widths();

    let mut derived = [0u8; POLY_KEY_SIZE];

    cipher.xor(&key, &nonce, 0, &mut derived);

    assert_eq!(
        derived.to_vec(),
        hex_to_bytes(published::ONE_TIME_KEY),
        "the first thirty-two bytes of the keystream at counter zero"
    );
}
