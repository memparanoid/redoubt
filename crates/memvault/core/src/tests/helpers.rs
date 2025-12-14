// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_test_utils::{apply_permutation, index_permutations};
use memaead::AeadApi;
use memaead::support::test_utils::{AeadMock, AeadMockBehaviour};
use memcodec::CodecBuffer;
use memcodec::support::test_utils::{CodecTestBreaker, CodecTestBreakerBehaviour};
use redoubt_zero::ZeroizationProbe;

use crate::error::CipherBoxError;
use crate::helpers::{
    decrypt_from, encrypt_into, encrypt_into_buffers, get_sizes, to_decryptable_mut_dyn,
    to_encryptable_mut_dyn,
};

use super::consts::NUM_FIELDS;

fn create_nonces(aead: &dyn AeadApi) -> [Vec<u8>; NUM_FIELDS] {
    let mut nonces = core::array::from_fn(|_| Vec::new());

    for nonce in nonces.iter_mut() {
        nonce.reserve_exact(aead.api_nonce_size());
        nonce.resize(aead.api_nonce_size(), 0u8);
    }

    nonces
}

fn create_tags(aead: &dyn AeadApi) -> [Vec<u8>; NUM_FIELDS] {
    let mut tags = core::array::from_fn(|_| Vec::new());

    for tag in tags.iter_mut() {
        tag.reserve_exact(aead.api_tag_size());
        tag.resize(aead.api_tag_size(), 0u8);
    }

    tags
}

// =============================================================================
// bytes_required overflow tests
// =============================================================================

#[test]
fn test_encrypt_into_propagates_bytes_required_overflow() {
    // Two elements with usize::MAX / 2 will overflow when summed.
    let mut test_breakers: [CodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceBytesRequiredOverflow, 10)
        } else {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::None, i << 2)
        }
    });

    let mut aead = AeadMock::new(AeadMockBehaviour::None);
    let aead_key = [0u8; 32];
    let mut nonces = create_nonces(&aead);
    let mut tags = create_tags(&aead);

    let fields = test_breakers
        .each_mut()
        .map(|tb| to_encryptable_mut_dyn(tb));

    let result = encrypt_into(fields, &mut aead, &aead_key, &mut nonces, &mut tags);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Overflow(_))));
}

// =============================================================================
// encrypt_into tests
// =============================================================================

#[test]
fn test_encrypt_into_ok() {
    let mut test_breakers = [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let mut aead = AeadMock::new(AeadMockBehaviour::None);
    let aead_key = [0u8; 32];
    let mut nonces = create_nonces(&aead);
    let mut tags = create_tags(&aead);

    let fields = test_breakers
        .each_mut()
        .map(|tb| to_encryptable_mut_dyn(tb));

    let result = encrypt_into(fields, &mut aead, &aead_key, &mut nonces, &mut tags);

    assert!(result.is_ok());
}

#[test]
fn test_encrypt_into_propagates_errors() {
    let mut test_breakers: [CodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceEncodeError, 10)
        } else {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::None, i << 2)
        }
    });

    let mut aead = AeadMock::new(AeadMockBehaviour::None);
    let aead_key = [0u8; 32];
    let mut nonces = create_nonces(&aead);
    let mut tags = create_tags(&aead);

    let fields = test_breakers
        .each_mut()
        .map(|tb| to_encryptable_mut_dyn(tb));

    let result = encrypt_into(fields, &mut aead, &aead_key, &mut nonces, &mut tags);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
}

// =============================================================================
// encrypt_into_buffers tests
// =============================================================================

#[test]
fn test_encrypt_into_buffers_propagates_bytes_required_overflow() {
    let mut test_breakers: [CodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceBytesRequiredOverflow, 10)
        } else {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::None, i << 2)
        }
    });

    let mut aead = AeadMock::new(AeadMockBehaviour::None);
    let aead_key = [0u8; 32];
    let mut nonces = create_nonces(&aead);
    let mut tags = create_tags(&aead);
    let mut buffers: [CodecBuffer; NUM_FIELDS] = core::array::from_fn(|_| CodecBuffer::with_capacity(10));
    let mut ciphertexts: [Vec<u8>; NUM_FIELDS] = core::array::from_fn(|_| vec![]);

    let fields = test_breakers
        .each_mut()
        .map(|tb| to_encryptable_mut_dyn(tb));

    let result = encrypt_into_buffers(
        fields,
        &mut aead,
        &aead_key,
        &mut nonces,
        &mut tags,
        &mut buffers,
        &mut ciphertexts,
    );

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));

    // Assert zeroization!
    assert!(buffers.is_zeroized());
    assert!(ciphertexts.is_zeroized());
}

// =============================================================================
// encrypt_into zeroization tests
// =============================================================================

/// Test zeroization when encode fails - exhaustive permutation test.
/// Flow: encode_into fails → buffers[0..i] have plaintext → must zeroize all.
#[test]
fn test_encrypt_into_buffers_performs_zeroization_on_encode_failure() {
    // CodecTestBreakers: one with ForceEncodeError at index 0, rest None.
    let test_breakers: [CodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceEncodeError, i << 2)
        } else {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::None, i << 2)
        }
    });

    let aead = AeadMock::new(AeadMockBehaviour::None);
    let aead_key = [0u8; 32];

    // Test ALL permutations (NUM_FIELDS! = 720).
    index_permutations(NUM_FIELDS, |perm| {
        let mut test_breakers_cpy = test_breakers;
        apply_permutation(&mut test_breakers_cpy, perm);

        let fields = test_breakers_cpy
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));
        let sizes = get_sizes(&fields).expect("Failed to get_sizes()");
        let mut buffers: [CodecBuffer; NUM_FIELDS] = sizes.map(CodecBuffer::with_capacity);
        let mut ciphertexts: [Vec<u8>; NUM_FIELDS] = core::array::from_fn(|_| vec![]);

        // Re-create fields after get_sizes consumed them.
        let fields = test_breakers_cpy
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));

        let mut aead_mock = AeadMock::new(AeadMockBehaviour::None);
        let mut nonces = create_nonces(&aead);
        let mut tags = create_tags(&aead);

        let result = encrypt_into_buffers(
            fields,
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut buffers,
            &mut ciphertexts,
        );

        assert!(result.is_err(), "encode should fail (perm: {:?})", perm);
        assert!(
            matches!(result, Err(CipherBoxError::Poisoned)),
            "should return Poisoned error (perm: {:?})",
            perm
        );

        // Assert zeroization!
        assert!(
            buffers.is_zeroized(),
            "postcondition failed: buffers must be zeroized (perm: {:?})",
            perm
        );
        assert!(
            ciphertexts.is_zeroized(),
            "postcondition failed: ciphertexts must be zeroized (perm: {:?})",
            perm
        );
    });
}

/// Test zeroization when generate_nonce fails at each position.
/// Flow: all encodes succeed → buffers have plaintext → nonce gen fails → must zeroize.
#[test]
fn test_encrypt_into_buffers_performs_zeroization_on_generate_nonce_failure() {
    let mut test_breakers = [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let aead_key = [0u8; 32];

    // Test failure at each position.
    for i in 0..NUM_FIELDS {
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));
        let sizes = get_sizes(&fields).expect("Failed to get_sizes()");
        let mut buffers: [CodecBuffer; NUM_FIELDS] = sizes.map(CodecBuffer::with_capacity);
        let mut ciphertexts: [Vec<u8>; NUM_FIELDS] = core::array::from_fn(|_| vec![]);
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));

        let mut aead_mock = AeadMock::new(AeadMockBehaviour::FailGenerateNonceAt(i));
        let mut nonces = create_nonces(&aead);
        let mut tags = create_tags(&aead);

        let result = encrypt_into_buffers(
            fields,
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut buffers,
            &mut ciphertexts,
        );

        assert!(result.is_err(), "nonce gen should fail at position {}", i);
        assert!(
            matches!(result, Err(CipherBoxError::Poisoned)),
            "should return Poisoned error at position {}",
            i
        );

        // Assert zeroization!
        assert!(
            buffers.is_zeroized(),
            "postcondition failed: buffers must be zeroized at position {}",
            i
        );
        assert!(
            ciphertexts.is_zeroized(),
            "postcondition failed: ciphertexts must be zeroized at position {}",
            i
        );
    }
}

/// Test zeroization when encrypt fails at each position.
/// Flow: all encodes succeed → buffers have plaintext → encrypt fails → must zeroize.
#[test]
fn test_encrypt_into_buffers_performs_zeroization_on_encrypt_failure() {
    let mut test_breakers = [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let aead_key = [0u8; 32];

    // Test failure at each position.
    for i in 0..NUM_FIELDS {
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));
        let sizes = get_sizes(&fields).expect("Failed to get_sizes()");
        let mut buffers: [CodecBuffer; NUM_FIELDS] = sizes.map(CodecBuffer::with_capacity);
        let mut ciphertexts: [Vec<u8>; NUM_FIELDS] = core::array::from_fn(|_| vec![]);
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));

        let mut aead_mock = AeadMock::new(AeadMockBehaviour::FailEncryptAt(i));
        let mut nonces = create_nonces(&aead);
        let mut tags = create_tags(&aead);

        let result = encrypt_into_buffers(
            fields,
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut buffers,
            &mut ciphertexts,
        );

        assert!(result.is_err(), "encrypt should fail at position {}", i);
        assert!(
            matches!(result, Err(CipherBoxError::Poisoned)),
            "should return Poisoned error at position {}",
            i
        );

        // Assert zeroization!
        assert!(
            buffers.is_zeroized(),
            "postcondition failed: buffers must be zeroized at position {}",
            i
        );
        assert!(
            ciphertexts.is_zeroized(),
            "postcondition failed: ciphertexts must be zeroized at position {}",
            i
        );
    }
}

#[test]
fn test_encrypt_into_buffers_ok() {
    let mut test_breakers = [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let mut aead = AeadMock::new(AeadMockBehaviour::None);
    let aead_key = [0u8; 32];

    let fields = test_breakers
        .each_mut()
        .map(|tb| to_encryptable_mut_dyn(tb));
    let sizes = get_sizes(&fields).expect("Failed to get_sizes()");
    let mut buffers: [CodecBuffer; NUM_FIELDS] = sizes.map(CodecBuffer::with_capacity);
    let mut ciphertexts: [Vec<u8>; NUM_FIELDS] = core::array::from_fn(|_| vec![]);
    let mut nonces = create_nonces(&aead);
    let mut tags = create_tags(&aead);

    let fields = test_breakers
        .each_mut()
        .map(|tb| to_encryptable_mut_dyn(tb));

    let result = encrypt_into_buffers(
        fields,
        &mut aead,
        &aead_key,
        &mut nonces,
        &mut tags,
        &mut buffers,
        &mut ciphertexts,
    );

    assert!(result.is_ok());

    // Assert zeroization!
    assert!(buffers.is_zeroized());
}

// =============================================================================
// decrypt_from zeroization tests
// =============================================================================

/// Test zeroization when AEAD decrypt fails at each position.
/// Flow: api_decrypt fails → ciphertexts[0..i] may have plaintext → must zeroize all.
#[test]
fn test_decrypt_from_zeroizes_on_decrypt_failure() {
    let mut test_breakers = [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let mut aead = AeadMock::new(AeadMockBehaviour::None);

    let aead_key = [0u8; 32];
    let mut nonces = create_nonces(&aead);
    let mut tags = create_tags(&aead);
    let ciphertexts = {
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));

        encrypt_into(fields, &mut aead, &aead_key, &mut nonces, &mut tags)
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
            &mut fields,
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut ciphertexts_clone,
        );
        assert!(result.is_ok(), "sanity check: decrypt should succeed");
    }

    // Test failure at each position i.
    for i in 0..NUM_FIELDS {
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
            &mut fields,
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut ciphertexts_clone,
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

/// Test zeroization when decode fails - exhaustive permutation test.
/// Flow: api_decrypt succeeds → ciphertexts become plaintext → decode_from fails → must zeroize all.
#[test]
fn test_decrypt_from_zeroizes_on_decode_failure() {
    let mut test_breakers: [CodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceDecodeError, i << 2)
        } else {
            CodecTestBreaker::new(CodecTestBreakerBehaviour::None, i << 2)
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
        encrypt_into(fields, &mut aead, &aead_key, &mut nonces, &mut tags)
            .expect("Failed to encrypt_into()")
    };

    // Sanity check: decrypt works with no errors.
    {
        let mut test_breakers = [CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
        let mut aead_mock = AeadMock::new(AeadMockBehaviour::None);
        let mut ciphertexts_clone = ciphertexts.clone();
        let mut fields = test_breakers
            .each_mut()
            .map(|tb| to_decryptable_mut_dyn(tb));
        let result = decrypt_from(
            &mut fields,
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut ciphertexts_clone,
        );
        assert!(result.is_ok(), "sanity check: decrypt should succeed");
    }

    // Test ALL permutations of behaviours (NUM_FIELDS! = 720 for NUM_FIELDS=6).
    // Each permutation places ForceDecodeError at a different position and order.
    index_permutations(NUM_FIELDS, |perm| {
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
            &mut fields,
            &mut aead_mock,
            &aead_key,
            &mut nonces,
            &mut tags,
            &mut ciphertexts_clone,
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
