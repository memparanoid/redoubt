// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use mem_test_utils::{apply_permutation, index_permutations};
use memaead::AeadApi;
use memaead::support::test_utils::{AeadMock, AeadMockBehaviour};
use memcodec::support::test_utils::{TestBreaker, TestBreakerBehaviour};
use memzer::ZeroizationProbe;

use crate::error::CipherBoxError;
use crate::helpers::{decrypt_from, encrypt_into, to_decryptable_mut_dyn, to_encryptable_mut_dyn};

static ELEMENTS: usize = 6;

fn create_nonces(aead: &dyn AeadApi) -> [Vec<u8>; ELEMENTS] {
    let mut nonces = core::array::from_fn(|_| Vec::new());

    for nonce in nonces.iter_mut() {
        nonce.reserve_exact(aead.api_nonce_size());
        nonce.resize(aead.api_nonce_size(), 0u8);
    }

    nonces
}

fn create_tags(aead: &dyn AeadApi) -> [Vec<u8>; ELEMENTS] {
    let mut tags = core::array::from_fn(|_| Vec::new());

    for tag in tags.iter_mut() {
        tag.reserve_exact(aead.api_tag_size());
        tag.resize(aead.api_tag_size(), 0u8);
    }

    tags
}

/// Test zeroization when AEAD decrypt fails at each position.
/// Flow: api_decrypt fails → ciphertexts[0..i] may have plaintext → must zeroize all.
#[test]
fn test_decrypt_from_zeroizes_on_decrypt_failure() {
    let mut test_breakers = [TestBreaker::new(TestBreakerBehaviour::None, 100); ELEMENTS];
    let mut aead = AeadMock::new(AeadMockBehaviour::None);

    let aead_key = [0u8; 32];
    let mut nonces = create_nonces(&aead);
    let mut tags = create_tags(&aead);
    let ciphertexts = {
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));

        encrypt_into(&mut aead, &aead_key, &mut nonces, &mut tags, fields)
            .expect("Failed to encrypt_into()")
    };

    // Sanity check: decrypt works with no errors.
    {
        let mut aead_mock = AeadMock::new(AeadMockBehaviour::None);
        let mut ciphertexts_clone = ciphertexts.clone();
        let mut fields = test_breakers
            .each_mut()
            .map(|tb| to_decryptable_mut_dyn(tb));
        let result = decrypt_from(
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut ciphertexts_clone,
            &mut fields,
        );
        assert!(result.is_ok(), "sanity check: decrypt should succeed");
    }

    // Test failure at each position i.
    for i in 0..ELEMENTS {
        let mut aead_mock = AeadMock::new(AeadMockBehaviour::FailDecryptAt(i));
        let mut ciphertexts_clone = ciphertexts.clone();
        let mut fields = test_breakers
            .each_mut()
            .map(|tb| to_decryptable_mut_dyn(tb));

        // CRUCIAL: Verify precondition - ciphertexts must contain data BEFORE the operation.
        // Without this check, the test would pass even if zeroization never happened
        // (e.g., if ciphertexts were already zero). We must prove the STATE CHANGE occurred,
        // not just that the final state is zero.
        assert!(
            !ciphertexts_clone.is_zeroized(),
            "precondition failed: ciphertexts must not be zeroized before decrypt"
        );

        let result = decrypt_from(
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut ciphertexts_clone,
            &mut fields,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(CipherBoxError::Poisoned)));

        // Postcondition: after failure, all ciphertexts must be zeroized.
        assert!(
            ciphertexts_clone.is_zeroized(),
            "postcondition failed: ciphertexts must be zeroized after decrypt failure"
        );
    }
}

#[test]
fn test_decrypt_from_zeroizes_on_decode_failure() {
    let mut test_breakers: [TestBreaker; ELEMENTS] = core::array::from_fn(|i| {
        if i == 0 {
            TestBreaker::new(TestBreakerBehaviour::ForceDecodeError, i << 2)
        } else {
            TestBreaker::new(TestBreakerBehaviour::None, i << 2)
        }
    });
    let mut aead = AeadMock::new(AeadMockBehaviour::None);

    // Generate valid ciphertexts first (all None behaviours).
    let aead_key = [0u8; 32];
    let mut nonces = create_nonces(&aead);
    let mut tags = create_tags(&aead);
    let ciphertexts = {
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));
        encrypt_into(&mut aead, &aead_key, &mut nonces, &mut tags, fields)
            .expect("Failed to encrypt_into()")
    };

    // Sanity check: decrypt works with no errors.
    {
        let mut test_breakers = [TestBreaker::new(TestBreakerBehaviour::None, 100); ELEMENTS];
        let mut aead_mock = AeadMock::new(AeadMockBehaviour::None);
        let mut ciphertexts_clone = ciphertexts.clone();
        let mut fields = test_breakers
            .each_mut()
            .map(|tb| to_decryptable_mut_dyn(tb));
        let result = decrypt_from(
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut ciphertexts_clone,
            &mut fields,
        );
        assert!(result.is_ok(), "sanity check: decrypt should succeed");
    }

    // Test ALL permutations of behaviours (ELEMENTS! = 720 for ELEMENTS=6).
    // Each permutation places ForceDecodeError at a different position and order.
    index_permutations(ELEMENTS, |perm| {
        // Apply permutation to behaviours.
        let mut test_breakers_cpy = test_breakers;
        apply_permutation(&mut test_breakers_cpy, perm);

        let mut aead_mock = AeadMock::new(AeadMockBehaviour::None);
        let mut ciphertexts_clone = ciphertexts.clone();
        let mut fields = test_breakers_cpy
            .each_mut()
            .map(|tb| to_decryptable_mut_dyn(tb));

        // CRUCIAL: Verify precondition.
        assert!(
            !ciphertexts_clone.is_zeroized(),
            "precondition failed: ciphertexts must not be zeroized before decrypt (perm: {:?})",
            perm
        );

        let result = decrypt_from(
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut ciphertexts_clone,
            &mut fields,
        );

        assert!(result.is_err(), "decode should fail (perm: {:?})", perm);
        assert!(
            matches!(result, Err(CipherBoxError::Poisoned)),
            "should return Poisoned error (perm: {:?})",
            perm
        );

        // Postcondition: after failure, all ciphertexts must be zeroized.
        assert!(
            ciphertexts_clone.is_zeroized(),
            "postcondition failed: ciphertexts must be zeroized (perm: {:?})",
            perm
        );
    });
}
