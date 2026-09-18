// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The Wycheproof corpora, against both implementations.
//!
//! What these reach that a standard's own vectors do not is the answers nobody
//! meant to publish: inputs picked because an implementation might get them
//! wrong, rather than because a document needed an example. A tag modified in
//! one bit, a salt of nothing, a length one past the last block.
//!
//! # A refused vector is an assertion of its own
//!
//! `Invalid` does not mean the call fails. For a tag it means the tag must not
//! match, which is the claim an implementation that compares only the first
//! bytes would break; for a derivation it means the length is one the counter
//! has no block for, which is a refusal the caller must see.
//!
//! # Why the derivation goes through the type
//!
//! The seam takes no refusal — it is handed a length that already fits. What
//! decides whether a length fits is `HkdfSha256::derive`, and the corpus asks
//! about exactly that, so the corpus is put to the type rather than to the
//! function under it.

use alloc::vec;

use rstest::rstest;

use redoubt_asm::Backend;

use crate::backend::hmac_sha256;
use crate::consts::HASH_SIZE;
use crate::error::HkdfError;
use crate::hkdf::HkdfSha256;

use super::from_hex;
use super::support::hkdf_sha256_wycheproof::TestResult as Derived;
use super::support::hkdf_sha256_wycheproof_vectors::test_vectors as derivations;
use super::support::hmac_sha256_wycheproof::TestResult as Authenticated;
use super::support::hmac_sha256_wycheproof_vectors::test_vectors as authentications;

/// What to do with a vector the corpus calls neither valid nor invalid.
///
/// `acceptable` is in the schema every Wycheproof corpus answers to, and it
/// means the behaviour is undefined: accepting is correct and so is refusing.
/// Neither corpus here publishes one, so there is no policy to write, and
/// writing one anyway would be asserting a choice nobody made.
///
/// The day a regeneration brings one, this is where it stops.
fn unacceptable(tc_id: usize, comment: &str) -> ! {
    panic!("tcId {tc_id}: {comment} — the corpus grew an `acceptable`, which needs a policy");
}

// ============================================================================
// hmac_sha256
// ============================================================================

/// Every tag the corpus publishes, and every tag it says must not match.
///
/// The refusals are the half a standard's vectors do not have: most of them are
/// a published tag with a bit turned over, and an implementation that stopped
/// comparing early would answer that every one of them is fine.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_hmac_answers_every_tag_wycheproof_publishes(#[case] backend: Backend) {
    for case in authentications() {
        let key = from_hex(&case.key);
        let msg = from_hex(&case.msg);
        let tag = from_hex(&case.tag);

        let mut out = [0_u8; HASH_SIZE];

        hmac_sha256(backend, &key, &msg, &mut out);

        let matched = tag.len() <= HASH_SIZE && out[..tag.len()] == tag[..];

        match case.result {
            Authenticated::Acceptable => unacceptable(case.tc_id, &case.comment),
            Authenticated::Valid => {
                assert!(
                    matched,
                    "tcId {}: {} {:?}",
                    case.tc_id, case.comment, case.flags
                );
            }
            Authenticated::Invalid => {
                assert!(
                    !matched,
                    "tcId {}: {} {:?}",
                    case.tc_id, case.comment, case.flags
                );
            }
        }
    }
}

// ============================================================================
// HkdfSha256::derive
// ============================================================================

/// Every output the corpus publishes, and every length it says has no answer.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_derive_answers_every_output_wycheproof_publishes(#[case] backend: Backend) {
    let deriving = HkdfSha256::new().with_backend(backend);

    for case in derivations() {
        let ikm = from_hex(&case.ikm);
        let salt = from_hex(&case.salt);
        let info = from_hex(&case.info);
        let okm = from_hex(&case.okm);

        let mut got = vec![0_u8; case.size];
        let answered = deriving.derive(&salt, &ikm, &info, &mut got);

        match case.result {
            Derived::Acceptable => unacceptable(case.tc_id, &case.comment),
            Derived::Valid => {
                assert_eq!(
                    answered,
                    Ok(()),
                    "tcId {}: {} {:?}",
                    case.tc_id,
                    case.comment,
                    case.flags,
                );
                assert_eq!(
                    got, okm,
                    "tcId {}: {} {:?}",
                    case.tc_id, case.comment, case.flags,
                );
            }
            Derived::Invalid => {
                assert_eq!(
                    answered,
                    Err(HkdfError::OutputTooLong),
                    "tcId {}: {} {:?}",
                    case.tc_id,
                    case.comment,
                    case.flags,
                );
            }
        }
    }
}
