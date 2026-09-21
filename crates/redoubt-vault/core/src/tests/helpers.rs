// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_aead::{Aead, AeadBehaviour};
use redoubt_codec::RedoubtCodecBuffer;
use redoubt_codec::support::test_utils::{
    RedoubtCodecTestBreaker, RedoubtCodecTestBreakerBehaviour,
};
use redoubt_test_utils::{apply_permutation, index_permutations};
use redoubt_zero::ZeroizationProbe;

use crate::error::CipherBoxError;
use crate::helpers::{
    decrypt_from, encrypt_into, encrypt_into_buffers, get_sizes, to_decryptable_mut_dyn,
    to_encryptable_mut_dyn,
};

use super::consts::NUM_FIELDS;

/// A key of the width whichever cipher this machine chose takes.
///
/// Not a constant: `Aead::default()` picks AEGIS where the hardware has AES
/// and XChaCha20-Poly1305 where it does not, and those take keys of different
/// widths. A fixed one would be refused on half the machines this runs on.
fn zero_key() -> Vec<u8> {
    vec![0_u8; Aead::default().key_size()]
}

fn create_nonces(aead: &Aead) -> [Vec<u8>; NUM_FIELDS] {
    let mut nonces = core::array::from_fn(|_| Vec::new());

    for nonce in nonces.iter_mut() {
        nonce.reserve_exact(aead.nonce_size());
        nonce.resize(aead.nonce_size(), 0u8);
    }

    nonces
}

fn create_tags(aead: &Aead) -> [Vec<u8>; NUM_FIELDS] {
    let mut tags = core::array::from_fn(|_| Vec::new());

    for tag in tags.iter_mut() {
        tag.reserve_exact(aead.tag_size());
        tag.resize(aead.tag_size(), 0u8);
    }

    tags
}

// =============================================================================
// bytes_required overflow tests
// =============================================================================

#[test]
fn test_encrypt_into_propagates_bytes_required_overflow() {
    // Two elements with usize::MAX / 2 will overflow when summed.
    let mut test_breakers: [RedoubtCodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            RedoubtCodecTestBreaker::new(
                RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
                10,
            )
        } else {
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i << 2)
        }
    });

    let mut aead = Aead::default();
    let aead_key = zero_key();
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
    let mut test_breakers =
        [RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let mut aead = Aead::default();
    let aead_key = zero_key();
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
    let mut test_breakers: [RedoubtCodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceEncodeError, 10)
        } else {
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i << 2)
        }
    });

    let mut aead = Aead::default();
    let aead_key = zero_key();
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
    let mut test_breakers: [RedoubtCodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            RedoubtCodecTestBreaker::new(
                RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
                10,
            )
        } else {
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i << 2)
        }
    });

    let mut aead = Aead::default();
    let aead_key = zero_key();
    let mut nonces = create_nonces(&aead);
    let mut tags = create_tags(&aead);
    let mut buffers: [RedoubtCodecBuffer; NUM_FIELDS] =
        core::array::from_fn(|_| RedoubtCodecBuffer::with_capacity(10));
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
    // RedoubtCodecTestBreakers: one with ForceEncodeError at index 0, rest None.
    let test_breakers: [RedoubtCodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceEncodeError, i << 2)
        } else {
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i << 2)
        }
    });

    let aead_key = zero_key();

    // Test ALL permutations (NUM_FIELDS! = 720).
    index_permutations(NUM_FIELDS, |perm| {
        let mut test_breakers_cpy = test_breakers;
        apply_permutation(&mut test_breakers_cpy, perm);

        let fields = test_breakers_cpy
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));
        let sizes = get_sizes(&fields).expect("Failed to get_sizes()");
        let mut buffers: [RedoubtCodecBuffer; NUM_FIELDS] =
            sizes.map(RedoubtCodecBuffer::with_capacity);
        let mut ciphertexts: [Vec<u8>; NUM_FIELDS] = core::array::from_fn(|_| vec![]);

        // Re-create fields after get_sizes consumed them.
        let fields = test_breakers_cpy
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));

        let mut aead = Aead::default();
        let mut nonces = create_nonces(&aead);
        let mut tags = create_tags(&aead);

        let result = encrypt_into_buffers(
            fields,
            &mut aead,
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
fn test_encrypt_into_buffers_performs_zeroization_on_generate_nonce_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let mut test_breakers =
        [RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let aead_key = zero_key();

    // Test failure at each position.
    for i in 0..NUM_FIELDS {
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));
        let sizes = get_sizes(&fields)?;
        let mut buffers: [RedoubtCodecBuffer; NUM_FIELDS] =
            sizes.map(RedoubtCodecBuffer::with_capacity);
        let mut ciphertexts: [Vec<u8>; NUM_FIELDS] = core::array::from_fn(|_| vec![]);
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));

        let mut aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthGenerateNonce(i + 1));
        let mut nonces = create_nonces(&aead);
        let mut tags = create_tags(&aead);

        let result = encrypt_into_buffers(
            fields,
            &mut aead,
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

    Ok(())
}

/// Test zeroization when encrypt fails at each position.
/// Flow: all encodes succeed → buffers have plaintext → encrypt fails → must zeroize.
#[test]
fn test_encrypt_into_buffers_performs_zeroization_on_encrypt_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let mut test_breakers =
        [RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let aead_key = zero_key();

    // Test failure at each position.
    for i in 0..NUM_FIELDS {
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));
        let sizes = get_sizes(&fields)?;
        let mut buffers: [RedoubtCodecBuffer; NUM_FIELDS] =
            sizes.map(RedoubtCodecBuffer::with_capacity);
        let mut ciphertexts: [Vec<u8>; NUM_FIELDS] = core::array::from_fn(|_| vec![]);
        let fields = test_breakers
            .each_mut()
            .map(|tb| to_encryptable_mut_dyn(tb));

        let mut aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(i + 1));
        let mut nonces = create_nonces(&aead);
        let mut tags = create_tags(&aead);

        let result = encrypt_into_buffers(
            fields,
            &mut aead,
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

    Ok(())
}

#[test]
fn test_encrypt_into_buffers_ok() -> Result<(), Box<dyn std::error::Error>> {
    let mut test_breakers =
        [RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let mut aead = Aead::default();
    let aead_key = zero_key();

    let fields = test_breakers
        .each_mut()
        .map(|tb| to_encryptable_mut_dyn(tb));
    let sizes = get_sizes(&fields)?;
    let mut buffers: [RedoubtCodecBuffer; NUM_FIELDS] =
        sizes.map(RedoubtCodecBuffer::with_capacity);
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

    Ok(())
}

// =============================================================================
// decrypt_from zeroization tests
// =============================================================================

/// Test zeroization when AEAD decrypt fails at each position.
/// Flow: api_decrypt fails → ciphertexts[0..i] may have plaintext → must zeroize all.
#[test]
fn test_decrypt_from_zeroizes_on_decrypt_failure() {
    let mut test_breakers =
        [RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
    let mut aead = Aead::default();

    let aead_key = zero_key();
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
        let aead = Aead::default();
        let mut ciphertexts_clone = ciphertexts.clone();
        let mut fields = test_breakers
            .each_mut()
            .map(|tb| to_decryptable_mut_dyn(tb));
        let result = decrypt_from(
            &mut fields,
            &aead,
            &aead_key,
            &nonces,
            &tags,
            &mut ciphertexts_clone,
        );
        assert!(result.is_ok(), "sanity check: decrypt should succeed");
    }

    // Test failure at each position i.
    for i in 0..NUM_FIELDS {
        let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(i + 1));
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
            &aead,
            &aead_key,
            &nonces,
            &tags,
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
    let mut test_breakers: [RedoubtCodecTestBreaker; NUM_FIELDS] = core::array::from_fn(|i| {
        if i == 0 {
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceDecodeError, i << 2)
        } else {
            RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i << 2)
        }
    });
    let mut aead = Aead::default();

    // Generate valid ciphertexts first (all None behaviours).
    let aead_key = zero_key();
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
        let mut test_breakers =
            [RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100); NUM_FIELDS];
        let aead = Aead::default();
        let mut ciphertexts_clone = ciphertexts.clone();
        let mut fields = test_breakers
            .each_mut()
            .map(|tb| to_decryptable_mut_dyn(tb));
        let result = decrypt_from(
            &mut fields,
            &aead,
            &aead_key,
            &nonces,
            &tags,
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

        let aead = Aead::default();
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
            &aead,
            &aead_key,
            &nonces,
            &tags,
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
