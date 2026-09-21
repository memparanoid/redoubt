// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The published corpus, against both backends.
//!
//! Three hundred and fifteen vectors, each built to catch something somebody
//! got wrong once: tags that exercise the final modular addition, Poly1305 keys
//! with a zero limb, empty associated data, lengths on and off a block
//! boundary. What the RFC vectors in `poly1305` and `chacha` pin is that the
//! primitives agree with their specifications; what this pins is that the
//! construction standing them together agrees with everybody else's.
//!
//! Every case runs twice, once through the portable Rust and once through
//! whatever the target has, because an assembly that answers differently is the
//! thing nobody would notice.

use std::vec::Vec;

use rstest::rstest;

use redoubt_aead_core::consts::chacha::{KEY_SIZE, XNONCE_SIZE};
use redoubt_aead_core::consts::poly1305::TAG_SIZE;
use redoubt_aead_core::{AeadDecrypt, AeadEncrypt, AeadError};
use redoubt_asm::Backend;
use redoubt_util::hex_to_bytes;

use crate::xchachapoly1305::XChaCha20Poly1305;

use super::support::wycheproof::{TestCase, TestResult};
use super::support::wycheproof_vectors::test_vectors;

/// The key and the nonce at the widths this construction takes, or nothing.
///
/// A vector whose nonce is not twenty-four bytes cannot be handed over at all —
/// the type says so — which is what the ignored shell at the end of this file
/// is about.
fn widths(case: &TestCase) -> Option<([u8; KEY_SIZE], [u8; XNONCE_SIZE])> {
    let key = hex_to_bytes(&case.key).try_into().ok()?;
    let nonce = hex_to_bytes(&case.iv).try_into().ok()?;

    Some((key, nonce))
}

// === === === === === === === === === ===
// encrypt
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_encrypt_returns_the_ciphertext_and_tag_the_corpus_publishes(#[case] backend: Backend) {
    let mut aead = XChaCha20Poly1305::with_backend(backend);
    let vectors = test_vectors();

    for case in vectors.iter() {
        // An invalid vector says nothing about enciphering: what it is invalid
        // about is the tag, which is the other direction.
        if matches!(case.result, TestResult::Invalid) {
            continue;
        }

        let Some((key, nonce)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);
        let mut data = hex_to_bytes(&case.msg);
        let mut tag = [0u8; TAG_SIZE];

        aead.encrypt(&key, &nonce, &aad, &mut data, &mut tag);

        assert_eq!(
            data,
            hex_to_bytes(&case.ct),
            "vector {} {:?} ({}): the ciphertext",
            case.tc_id,
            case.flags,
            case.comment
        );

        assert_eq!(
            tag.to_vec(),
            hex_to_bytes(&case.tag),
            "vector {} {:?} ({}): the tag",
            case.tc_id,
            case.flags,
            case.comment
        );
    }
}

// === === === === === === === === === ===
// decrypt
// === === === === === === === === === ===

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_decrypt_accepts_what_the_corpus_calls_valid(#[case] backend: Backend) {
    let mut aead = XChaCha20Poly1305::with_backend(backend);
    let vectors = test_vectors();

    for case in vectors.iter() {
        if matches!(case.result, TestResult::Invalid) {
            continue;
        }

        let Some((key, nonce)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);
        let mut data = hex_to_bytes(&case.ct);
        let Ok(tag): Result<[u8; TAG_SIZE], _> = hex_to_bytes(&case.tag).try_into() else {
            continue;
        };

        aead.decrypt(&key, &nonce, &aad, &mut data, &tag)
            .unwrap_or_else(|_| {
                panic!(
                    "vector {} {:?} ({}) is one the corpus calls valid",
                    case.tc_id, case.flags, case.comment
                )
            });

        assert_eq!(
            data,
            hex_to_bytes(&case.msg),
            "vector {} {:?} ({}): the plaintext",
            case.tc_id,
            case.flags,
            case.comment
        );
    }
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_decrypt_refuses_what_the_corpus_calls_invalid(#[case] backend: Backend) {
    let mut aead = XChaCha20Poly1305::with_backend(backend);
    let vectors = test_vectors();

    for case in vectors.iter() {
        if matches!(case.result, TestResult::Valid) {
            continue;
        }

        let Some((key, nonce)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);
        let mut data = hex_to_bytes(&case.ct);
        let Ok(tag): Result<[u8; TAG_SIZE], _> = hex_to_bytes(&case.tag).try_into() else {
            continue;
        };

        let refused = aead.decrypt(&key, &nonce, &aad, &mut data, &tag);

        assert_eq!(
            refused,
            Err(AeadError::AuthenticationFailed),
            "vector {} {:?} ({}) is one the corpus calls invalid",
            case.tc_id,
            case.flags,
            case.comment
        );
    }
}

/// Every tag the corpus calls good, with one bit turned over.
///
/// The corpus already carries tags that were tampered with, and this is the
/// other half: for each vector that must be accepted, the same vector must be
/// refused once a single bit moves. A verification that compared a prefix, or
/// that stopped at the first difference, passes the corpus and fails here.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_decrypt_refuses_a_tag_with_one_bit_turned_over(#[case] backend: Backend) {
    let mut aead = XChaCha20Poly1305::with_backend(backend);
    let vectors = test_vectors();

    for case in vectors.iter() {
        if matches!(case.result, TestResult::Invalid) {
            continue;
        }

        let Some((key, nonce)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);
        let Ok(mut tag): Result<[u8; TAG_SIZE], _> = hex_to_bytes(&case.tag).try_into() else {
            continue;
        };

        for bit in 0..8 {
            let mut data = hex_to_bytes(&case.ct);

            tag[0] ^= 1 << bit;

            let refused = aead.decrypt(&key, &nonce, &aad, &mut data, &tag);

            tag[0] ^= 1 << bit;

            assert_eq!(
                refused,
                Err(AeadError::AuthenticationFailed),
                "vector {} {:?} ({}): bit {bit} of the tag turned over and it was taken",
                case.tc_id,
                case.flags,
                case.comment
            );
        }
    }
}

// === === === === === === === === === ===
// encrypt and decrypt, one after the other
// === === === === === === === === === ===

/// What came out of the corpus goes back into it.
///
/// Each direction above is held to a published answer, so the two agreeing with
/// each other cannot fail while both of those pass. It is here because a suite
/// called Wycheproof runs what Wycheproof means, and because the day one of the
/// two directions is changed, this is the test that says the pair came apart
/// before anybody reads which published value moved.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_decrypt_then_encrypt_returns_the_corpus_to_itself(#[case] backend: Backend) {
    let mut aead = XChaCha20Poly1305::with_backend(backend);
    let vectors = test_vectors();

    for case in vectors.iter() {
        if matches!(case.result, TestResult::Invalid) {
            continue;
        }

        let Some((key, nonce)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);
        let sealed = hex_to_bytes(&case.ct);
        let mut data = sealed.clone();
        let Ok(published): Result<[u8; TAG_SIZE], _> = hex_to_bytes(&case.tag).try_into() else {
            continue;
        };

        aead.decrypt(&key, &nonce, &aad, &mut data, &published)
            .unwrap_or_else(|_| {
                panic!(
                    "vector {} {:?} ({}) is one the corpus calls valid",
                    case.tc_id, case.flags, case.comment
                )
            });

        let mut again = [0u8; TAG_SIZE];

        aead.encrypt(&key, &nonce, &aad, &mut data, &mut again);

        assert_eq!(
            data, sealed,
            "vector {} {:?} ({}): the ciphertext, sealed again",
            case.tc_id, case.flags, case.comment
        );

        assert_eq!(
            again, published,
            "vector {} {:?} ({}): the tag, taken again",
            case.tc_id, case.flags, case.comment
        );
    }
}

// === === === === === === === === === ===
// The vectors nothing here can hand over
// === === === === === === === === === ===

/// Uncovered: the corpus carries vectors whose nonce is not twenty-four bytes,
/// and this construction takes `&[u8; 24]`. There is no way to spell handing
/// one over, so there is no behaviour to check: what would have rejected it at
/// run time rejects it at compile time instead, which is what naming the widths
/// in [`redoubt_aead_core::AeadSizes`] was for.
///
/// The shell is here so that the vectors this file skips are named rather than
/// silently counted as passing, and so the day the API takes a slice again
/// somebody finds the test that was owed.
#[test]
#[ignore = "Uncovered: a nonce of the wrong width cannot be passed to an API that \
            takes an array, so these vectors have no call to make. Shell preserved \
            in case the widths ever stop being types."]
fn test_decrypt_refuses_a_nonce_of_the_wrong_width() {
    // Intentionally empty.
}

/// The same, for the tag.
///
/// Uncovered for the same reason and worth its own shell, because the two are
/// different widths owed by different halves of the construction.
#[test]
#[ignore = "Uncovered: a tag of the wrong width cannot be passed to an API that \
            takes an array. Shell preserved in case the widths ever stop being \
            types."]
fn test_decrypt_refuses_a_tag_of_the_wrong_width() {
    // Intentionally empty.
}

/// How many the two above account for.
///
/// Not an assertion about the construction: an assertion about this file. If the
/// corpus grows a family that `widths` quietly drops, the number moves and
/// somebody has to look at why.
#[test]
fn test_the_corpus_is_all_reached_but_the_ones_of_the_wrong_width() {
    let vectors = test_vectors();

    let skipped: Vec<usize> = vectors
        .iter()
        .filter(|case| widths(case).is_none())
        .map(|case| case.tc_id)
        .collect();

    assert!(
        skipped.len() * 20 < vectors.len(),
        "{} of {} vectors are being skipped for their widths, which is more than \
         a family of edge cases: {skipped:?}",
        skipped.len(),
        vectors.len(),
    );
}
