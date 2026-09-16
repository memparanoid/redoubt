// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Every vector draft-irtf-cfrg-aegis-aead publishes for AEGIS-128L.
//!
//! The draft prints a 256-bit tag beside each 128-bit one. That is the other
//! variant of the same construction and this crate does not implement it, so
//! only `tag128` appears below.
//!
//! That a rejected message leaves the caller's buffer empty is required by the
//! same pseudocode and asserted elsewhere: it is a claim about zeroization
//! rather than about arithmetic.

use rstest::rstest;

use redoubt_aead_v2_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use redoubt_aead_v2_core::{AeadDecrypt, AeadEncrypt, AeadError};
use redoubt_util::hex_to_bytes;

use crate::aegis128l::Aegis128L;

/// draft-irtf-cfrg-aegis-aead-17, appendix A.2.
///
/// The draft prints each of these across continuation lines; here every one is
/// a single string, because a byte lost while rewrapping leaves a total that
/// still looks right.
#[rustfmt::skip]
mod published {
    pub(super) const KEY: &str = "10010000000000000000000000000000";
    pub(super) const NONCE: &str = "10000200000000000000000000000000";

    // A.2.2, test vector 1.
    pub(super) const MSG_1: &str = "00000000000000000000000000000000";
    pub(super) const CT_1: &str = "c1c0e58bd913006feba00f4b3cc3594e";
    pub(super) const TAG_1: &str = "abe0ece80c24868a226a35d16bdae37a";

    // A.2.3, test vector 2: nothing at all, which still has a tag.
    pub(super) const TAG_2: &str = "c2b879a67def9d74e6c14f708bbcc9b4";

    // A.2.4, test vector 3.
    pub(super) const AD_3: &str = "0001020304050607";
    pub(super) const MSG_3: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    pub(super) const CT_3: &str = "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84";
    pub(super) const TAG_3: &str = "cc6f3372f6aa1bb82388d695c3962d9a";

    // A.2.5, test vector 4: a message that stops inside a block. The four
    // rejections below are all this one with something moved.
    pub(super) const MSG_4: &str = "000102030405060708090a0b0c0d";
    pub(super) const CT_4: &str = "79d94593d8c2119d7e8fd9b8fc77";
    pub(super) const TAG_4: &str = "5c04b3dba849b2701effbe32c7f0fab7";

    // A.2.6, test vector 5: both the AAD and the message end on a tail.
    pub(super) const AD_5: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829";
    pub(super) const MSG_5: &str = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
    pub(super) const CT_5: &str = "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10";
    pub(super) const TAG_5: &str = "7542a745733014f9474417b337399507";

    // A.2.7, test vector 6: vector 4 with the key and the nonce exchanged.
    pub(super) const KEY_6: &str = "10000200000000000000000000000000";
    pub(super) const NONCE_6: &str = "10010000000000000000000000000000";

    // A.2.8, test vector 7: vector 4 with the last byte of the ciphertext
    // moved from 0x77 to 0x78.
    pub(super) const CT_7: &str = "79d94593d8c2119d7e8fd9b8fc78";

    // A.2.9, test vector 8: vector 4 with the last byte of the associated data
    // moved from 0x07 to 0x08.
    pub(super) const AD_8: &str = "0001020304050608";

    // A.2.10, test vector 9: vector 4 with the first and last bytes of the tag
    // moved.
    pub(super) const TAG_9: &str = "6c04b3dba849b2701effbe32c7f0fab8";
}

/// A key and a nonce at the widths the construction takes.
fn widths(key: &str, nonce: &str) -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    let key = hex_to_bytes(key)
        .try_into()
        .expect("a published key is sixteen bytes");

    let nonce = hex_to_bytes(nonce)
        .try_into()
        .expect("a published nonce is sixteen bytes");

    (key, nonce)
}

/// A tag at the width the construction writes.
fn tag_of(tag: &str) -> [u8; TAG_SIZE] {
    hex_to_bytes(tag)
        .try_into()
        .expect("a published tag is sixteen bytes")
}

// === === === === === === === === === ===
// encrypt
// === === === === === === === === === ===

#[rstest]
#[case::vector_1("", published::MSG_1, published::CT_1, published::TAG_1)]
#[case::vector_2("", "", "", published::TAG_2)]
#[case::vector_3(published::AD_3, published::MSG_3, published::CT_3, published::TAG_3)]
#[case::vector_4(published::AD_3, published::MSG_4, published::CT_4, published::TAG_4)]
#[case::vector_5(published::AD_5, published::MSG_5, published::CT_5, published::TAG_5)]
fn test_encrypt_returns_the_published_ciphertext_and_tag(
    #[case] ad: &str,
    #[case] msg: &str,
    #[case] ct: &str,
    #[case] expected: &str,
) {
    let mut aead = Aegis128L::new();
    let (key, nonce) = widths(published::KEY, published::NONCE);

    let aad = hex_to_bytes(ad);
    let mut data = hex_to_bytes(msg);
    let mut tag = [0u8; TAG_SIZE];

    aead.encrypt(&key, &nonce, &aad, &mut data, &mut tag);

    assert_eq!(data, hex_to_bytes(ct), "the ciphertext");
    assert_eq!(tag.to_vec(), hex_to_bytes(expected), "the tag");
}

// === === === === === === === === === ===
// decrypt
// === === === === === === === === === ===

#[rstest]
#[case::vector_1("", published::CT_1, published::TAG_1, published::MSG_1)]
#[case::vector_2("", "", published::TAG_2, "")]
#[case::vector_3(published::AD_3, published::CT_3, published::TAG_3, published::MSG_3)]
#[case::vector_4(published::AD_3, published::CT_4, published::TAG_4, published::MSG_4)]
#[case::vector_5(published::AD_5, published::CT_5, published::TAG_5, published::MSG_5)]
fn test_decrypt_returns_the_published_plaintext(
    #[case] ad: &str,
    #[case] ct: &str,
    #[case] tag: &str,
    #[case] expected: &str,
) {
    let mut aead = Aegis128L::new();
    let (key, nonce) = widths(published::KEY, published::NONCE);

    let aad = hex_to_bytes(ad);
    let mut data = hex_to_bytes(ct);

    aead.decrypt(&key, &nonce, &aad, &mut data, &tag_of(tag))
        .expect("the published tag is the one that sealed this");

    assert_eq!(data, hex_to_bytes(expected), "the plaintext");
}

/// The four the draft says MUST come back as a verification failure.
///
/// One for each thing the answer depends on, so that a construction which
/// forgot any of them fails here and says which: what it was keyed with, the
/// ciphertext, the associated data, and the tag.
#[rstest]
#[case::exchanged_key_and_nonce(
    published::KEY_6,
    published::NONCE_6,
    published::AD_3,
    published::CT_4,
    published::TAG_4
)]
#[case::moved_ciphertext(
    published::KEY,
    published::NONCE,
    published::AD_3,
    published::CT_7,
    published::TAG_4
)]
#[case::moved_associated_data(
    published::KEY,
    published::NONCE,
    published::AD_8,
    published::CT_4,
    published::TAG_4
)]
#[case::moved_tag(
    published::KEY,
    published::NONCE,
    published::AD_3,
    published::CT_4,
    published::TAG_9
)]
fn test_decrypt_rejects_what_the_draft_says_it_must(
    #[case] key: &str,
    #[case] nonce: &str,
    #[case] ad: &str,
    #[case] ct: &str,
    #[case] tag: &str,
) {
    let mut aead = Aegis128L::new();
    let (key, nonce) = widths(key, nonce);

    let aad = hex_to_bytes(ad);
    let mut data = hex_to_bytes(ct);

    let answer = aead.decrypt(&key, &nonce, &aad, &mut data, &tag_of(tag));

    assert_eq!(
        answer,
        Err(AeadError::AuthenticationFailed),
        "a vector the draft says must be rejected was accepted"
    );
}
