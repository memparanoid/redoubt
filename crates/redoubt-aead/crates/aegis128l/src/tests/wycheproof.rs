// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The published corpus.
//!
//! Four hundred and seventy-nine vectors, each built to catch something
//! somebody got wrong once: tags with a bit moved, two messages under one tag,
//! two associated data under one tag, and four sealed by the AEGIS of the
//! original paper, which is a different construction wearing the same name.
//! What the draft's vectors in `rfc` pin is agreement with the specification;
//! what this pins is agreement with everybody else who implemented it.
//!
//! One backend, so each of these runs once. There is nothing to compare against
//! within the crate — see the crate documentation for why there is no portable
//! implementation to disagree with.

use std::vec::Vec;

use redoubt_aead_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use redoubt_aead_core::{AeadDecrypt, AeadEncrypt, AeadError};
use redoubt_util::hex_to_bytes;

use crate::aegis128l::Aegis128L;

use super::support::wycheproof::{TestCase, TestResult};
use super::support::wycheproof_vectors::test_vectors;

/// The vectors, sampled with a fixed stride under Miri.
///
/// They are not interchangeable: each targets a distinct edge, so a prefix
/// would drop whole families and a stride lands across all of them.
///
/// Sampling is sound for what Miri is doing. It looks for undefined behaviour
/// on a code path, and the path is the same for vector three and vector four
/// hundred; what changes between them is the arithmetic, which Miri does not
/// check and which the ordinary run verifies exhaustively in seconds.
fn corpus(vectors: &[TestCase]) -> impl Iterator<Item = &TestCase> {
    #[cfg(miri)]
    let step = (vectors.len() / 16).max(1);

    #[cfg(not(miri))]
    let step = 1;

    vectors.iter().step_by(step)
}

/// The key, the nonce and the tag at the widths this construction takes.
///
/// Every vector in the corpus has all three, which the last test in this file
/// is what says: nothing below is skipped, so nothing below can pass by being
/// skipped.
fn widths(case: &TestCase) -> Option<([u8; KEY_SIZE], [u8; NONCE_SIZE], [u8; TAG_SIZE])> {
    let key = hex_to_bytes(&case.key).try_into().ok()?;
    let nonce = hex_to_bytes(&case.iv).try_into().ok()?;
    let tag = hex_to_bytes(&case.tag).try_into().ok()?;

    Some((key, nonce, tag))
}

// === === === === === === === === === ===
// encrypt
// === === === === === === === === === ===

#[test]
fn test_encrypt_returns_the_ciphertext_and_tag_the_corpus_publishes() {
    let mut aead = Aegis128L::new();
    let vectors = test_vectors();

    for case in corpus(&vectors) {
        // An invalid vector says nothing about enciphering: what it is invalid
        // about is the tag, which is the other direction.
        if matches!(case.result, TestResult::Invalid) {
            continue;
        }

        let Some((key, nonce, _)) = widths(case) else {
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

#[test]
fn test_decrypt_accepts_what_the_corpus_calls_valid() {
    let mut aead = Aegis128L::new();
    let vectors = test_vectors();

    for case in corpus(&vectors) {
        if matches!(case.result, TestResult::Invalid) {
            continue;
        }

        let Some((key, nonce, tag)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);
        let mut data = hex_to_bytes(&case.ct);

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

#[test]
fn test_decrypt_refuses_what_the_corpus_calls_invalid() {
    let mut aead = Aegis128L::new();
    let vectors = test_vectors();

    for case in corpus(&vectors) {
        if matches!(case.result, TestResult::Valid) {
            continue;
        }

        let Some((key, nonce, tag)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);
        let mut data = hex_to_bytes(&case.ct);

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

/// Every vector the corpus refuses leaves the caller's buffer empty.
///
/// The draft requires it in the same sentence as the error, and for AEGIS it is
/// what makes the error mean anything: one pass, so the plaintext is in the
/// buffer before there is a tag to compare, and a caller that ignores the
/// result reads it.
///
/// A ciphertext that is empty or already zero is skipped, and that is what
/// makes the assertion worth something: on one of those it would hold without a
/// wipe having run.
#[test]
fn test_decrypt_empties_the_buffer_of_what_the_corpus_refuses() {
    let mut aead = Aegis128L::new();
    let vectors = test_vectors();

    for case in corpus(&vectors) {
        if matches!(case.result, TestResult::Valid) {
            continue;
        }

        let Some((key, nonce, tag)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);
        let mut data = hex_to_bytes(&case.ct);

        if data.iter().all(|&byte| byte == 0) {
            continue;
        }

        assert!(
            data.iter().any(|&byte| byte != 0),
            "vector {} {:?} ({}): the control, before the call",
            case.tc_id,
            case.flags,
            case.comment
        );

        let _ = aead.decrypt(&key, &nonce, &aad, &mut data, &tag);

        // Assert zeroization!
        assert!(
            data.iter().all(|&byte| byte == 0),
            "vector {} {:?} ({}): a plaintext nothing authenticated was left behind",
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
#[test]
fn test_decrypt_refuses_a_tag_with_one_bit_turned_over() {
    let mut aead = Aegis128L::new();
    let vectors = test_vectors();

    for case in corpus(&vectors) {
        if matches!(case.result, TestResult::Invalid) {
            continue;
        }

        let Some((key, nonce, mut tag)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);

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
// decrypt and encrypt, one after the other
// === === === === === === === === === ===

/// What came out of the corpus goes back into it.
///
/// Each direction above is held to a published answer, so the two agreeing with
/// each other cannot fail while both of those pass. It is here because a suite
/// called Wycheproof runs what Wycheproof means, and because the day one of the
/// two directions is changed, this is the test that says the pair came apart
/// before anybody reads which published value moved.
#[test]
fn test_decrypt_then_encrypt_returns_the_corpus_to_itself() {
    let mut aead = Aegis128L::new();
    let vectors = test_vectors();

    for case in corpus(&vectors) {
        if matches!(case.result, TestResult::Invalid) {
            continue;
        }

        let Some((key, nonce, published)) = widths(case) else {
            continue;
        };

        let aad = hex_to_bytes(&case.aad);
        let sealed = hex_to_bytes(&case.ct);
        let mut data = sealed.clone();

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
// What the corpus holds
// === === === === === === === === === ===

/// Nothing above skips a vector for its widths.
///
/// Not an assertion about AEGIS: an assertion about this file. Every key, nonce
/// and tag the corpus publishes is sixteen bytes, so every `else { continue }`
/// above is unreachable — and the day the corpus grows a family of another
/// width, this says so rather than letting those vectors be counted as passing
/// while never running.
#[test]
fn test_every_vector_has_the_widths_this_crate_takes() {
    let vectors = test_vectors();

    let skipped: Vec<usize> = vectors
        .iter()
        .filter(|case| widths(case).is_none())
        .map(|case| case.tc_id)
        .collect();

    assert!(
        skipped.is_empty(),
        "{} of {} vectors have widths this crate cannot be handed: {skipped:?}",
        skipped.len(),
        vectors.len(),
    );
}
