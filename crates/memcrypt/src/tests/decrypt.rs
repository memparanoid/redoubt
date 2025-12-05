// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::{Aead, AeadError};
use memcodec::DecodeError;
use memcodec::support::test_utils::{
    TestBreaker, TestBreakerBehaviour, tamper_encoded_bytes_for_tests,
};
use memzer::ZeroizationProbe;

use crate::decrypt::{DecryptStage, decrypt_decodable_with};
use crate::encrypt::encrypt_encodable;
use crate::error::CryptoError;
use crate::guards::DecryptionMemZer;

use super::utils::{create_aead_key, create_nonce};

#[test]
fn test_decrypt_decodable_stage_validate_ciphertext_len_failure() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut ciphertext = Vec::<u8>::new();

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut nonce, &mut ciphertext);

    let result = decrypt_decodable_with::<TestBreaker, _>(&mut aead, &mut x, |_, _| {});

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CryptoError::CiphertextWithTagTooShort)
    ));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_decrypt_decodable_stage_decrypt_failure() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut ciphertext = {
        let mut aead = Aead::new();
        let mut aead_key_clone = aead_key.clone();
        let mut nonce_clone = nonce.clone();

        encrypt_encodable(
            &mut aead,
            &mut aead_key_clone,
            &mut nonce_clone,
            &mut test_breaker,
        )
        .expect("Failed to encrypt_serializable(..)")
    };

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut nonce, &mut ciphertext);

    let result =
        decrypt_decodable_with::<TestBreaker, _>(&mut aead, &mut x, |stage, x| match stage {
            DecryptStage::ValidateCiphertextWithTagLen => {}
            DecryptStage::Decrypt => {
                x.aead_key_size = 12; // Too small for XChacha20Poly1305 & Aegis128L
            }
            DecryptStage::Decode => {
                unreachable!("Decrypt algorithm will fail at DecryptStage::Decrypt")
            }
        });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CryptoError::Aead(AeadError::InvalidKeySize))
    ));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_decrypt_decodable_stage_decode_failure() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let mut test_breaker = TestBreaker::new(TestBreakerBehaviour::None, 100);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut ciphertext = {
        let mut aead = Aead::new();
        let mut aead_key_clone = aead_key.clone();
        let mut nonce_clone = nonce.clone();

        encrypt_encodable(
            &mut aead,
            &mut aead_key_clone,
            &mut nonce_clone,
            &mut test_breaker,
        )
        .expect("Failed to encrypt_serializable(..)")
    };

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut nonce, &mut ciphertext);

    let result =
        decrypt_decodable_with::<TestBreaker, _>(&mut aead, &mut x, |stage, x| match stage {
            DecryptStage::ValidateCiphertextWithTagLen => {}
            DecryptStage::Decrypt => {}
            DecryptStage::Decode => {
                tamper_encoded_bytes_for_tests(&mut x.ciphertext_with_tag);
            }
        });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CryptoError::Decode(DecodeError::IntentionalDecodeError))
    ));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_decrypt_decodable_ok() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let test_breaker = TestBreaker::new(TestBreakerBehaviour::None, 100);
    let mut test_breaker_clone = test_breaker.clone();

    // Assert (not) zeroization!
    assert!(!test_breaker_clone.is_zeroized());

    let mut ciphertext = {
        let mut aead = Aead::new();
        let mut aead_key_clone = aead_key.clone();
        let mut nonce_clone = nonce.clone();

        encrypt_encodable(
            &mut aead,
            &mut aead_key_clone,
            &mut nonce_clone,
            &mut test_breaker_clone,
        )
        .expect("Failed to encrypt_serializable(..)")
    };

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut nonce, &mut ciphertext);
    let recovered = decrypt_decodable_with::<TestBreaker, _>(&mut aead, &mut x, |_, _| {})
        .expect("Failed to decrypt_decodable_with(..)");

    assert_eq!(test_breaker, *recovered);

    // Assert zeroization!
    assert!(x.is_zeroized());
}
