// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memcodec::tamper_encoded_bytes_for_tests;
use memzer::ZeroizationProbe;

use crate::decrypt::{DecryptStage, decrypt_mem_decodable_with};
use crate::encrypt::encrypt_mem_encodable;
use crate::error::CryptoError;
use crate::guards::DecryptionMemZer;

use super::support::{TestBreaker, TestBreakerBehaviour, create_key_from_array, create_xnonce_from_array};

#[test]
fn test_decrypt_mem_decodable_stage_new_from_slice_failure() {
    let mut aead_key = create_key_from_array([1u8; 32]);
    let mut xnonce = create_xnonce_from_array([2u8; 24]);
    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut ciphertext = {
        let mut aead_key_clone = create_key_from_array([1u8; 32]);
        let mut xnonce_clone = create_xnonce_from_array([2u8; 24]);
        encrypt_mem_encodable(&mut aead_key_clone, &mut xnonce_clone, &mut test_breaker)
            .expect("Failed to encrypt_serializable(..)")
    };

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut xnonce, &mut ciphertext);

    let result =
        decrypt_mem_decodable_with::<TestBreaker, _>(&mut x, |stage, x| match stage {
            DecryptStage::NewFromSlice => {
                x.aead_key_size = 16;
            }
            DecryptStage::AeadBufferFillWithCiphertext
            | DecryptStage::Decrypt
            | DecryptStage::DrainFrom => {
                unreachable!("Decrypt algorithm will fail at DecryptStage::NewFromSlice")
            }
        });

    assert!(result.is_err());
    assert!(matches!(result, Err(CryptoError::InvalidKeyLength)));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_decrypt_mem_decodable_stage_aead_buffer_fill_with_ciphertext_failure() {
    let mut aead_key = create_key_from_array([1u8; 32]);
    let mut xnonce = create_xnonce_from_array([2u8; 24]);
    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut ciphertext = {
        let mut aead_key_clone = create_key_from_array([1u8; 32]);
        let mut xnonce_clone = create_xnonce_from_array([2u8; 24]);
        encrypt_mem_encodable(&mut aead_key_clone, &mut xnonce_clone, &mut test_breaker)
            .expect("Failed to encrypt_serializable(..)")
    };

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut xnonce, &mut ciphertext);

    let result =
        decrypt_mem_decodable_with::<TestBreaker, _>(&mut x, |stage, x| match stage {
            DecryptStage::NewFromSlice => {}
            DecryptStage::AeadBufferFillWithCiphertext => {
                x.aead_buffer
                    .zeroized_reserve_exact(3)
                    .expect("Failed to zeroized_reserve_exact()");
                x.aead_buffer
                    .drain_slice(&mut [1, 2, 3])
                    .expect("Failed to drain_slice()");
            }
            DecryptStage::Decrypt | DecryptStage::DrainFrom => {
                unreachable!("Decrypt algorithm will fail at DecryptStage::NewFromSlice")
            }
        });

    assert!(result.is_err());
    assert!(matches!(result, Err(CryptoError::AeadBufferNotZeroized)));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_decrypt_mem_decodable_stage_decrypt_failure() {
    let mut aead_key = create_key_from_array([1u8; 32]);
    let mut xnonce = create_xnonce_from_array([2u8; 24]);
    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut ciphertext = {
        let mut aead_key_clone = create_key_from_array([1u8; 32]);
        let mut xnonce_clone = create_xnonce_from_array([2u8; 24]);
        encrypt_mem_encodable(&mut aead_key_clone, &mut xnonce_clone, &mut test_breaker)
            .expect("Failed to encrypt_serializable(..)")
    };

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut xnonce, &mut ciphertext);

    let result = decrypt_mem_decodable_with::<TestBreaker, _>(&mut x, |stage, x| {
        match stage {
            DecryptStage::NewFromSlice => {}
            DecryptStage::AeadBufferFillWithCiphertext => {}
            DecryptStage::Decrypt => {
                // Tamper aead_buffer (ciphertext already copied there)
                x.aead_buffer.tamper(|bytes| bytes[0] ^= 1);
            }
            DecryptStage::DrainFrom => {
                unreachable!("Decrypt algorithm will fail at DecryptStage::Decrypt")
            }
        }
    });

    assert!(result.is_err());
    assert!(matches!(result, Err(CryptoError::Decrypt)));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_decrypt_mem_decodable_stage_drain_from_failure() {
    let mut aead_key = create_key_from_array([1u8; 32]);
    let mut xnonce = create_xnonce_from_array([2u8; 24]);
    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut ciphertext = {
        let mut aead_key_clone = create_key_from_array([1u8; 32]);
        let mut xnonce_clone = create_xnonce_from_array([2u8; 24]);
        encrypt_mem_encodable(&mut aead_key_clone, &mut xnonce_clone, &mut test_breaker)
            .expect("Failed to encrypt_serializable(..)")
    };

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut xnonce, &mut ciphertext);

    let result =
        decrypt_mem_decodable_with::<TestBreaker, _>(&mut x, |stage, x| match stage {
            DecryptStage::NewFromSlice => {}
            DecryptStage::AeadBufferFillWithCiphertext => {}
            DecryptStage::Decrypt => {}
            DecryptStage::DrainFrom => {
                x.aead_buffer.tamper(|bytes| {
                    tamper_encoded_bytes_for_tests(bytes);
                });
            }
        });

    assert!(result.is_err());
    assert!(matches!(result, Err(CryptoError::Decode(_))));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_decrypt_mem_decodable_ok() {
    let mut aead_key = create_key_from_array([1u8; 32]);
    let mut xnonce = create_xnonce_from_array([2u8; 24]);
    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut ciphertext = {
        let mut aead_key_clone = create_key_from_array([1u8; 32]);
        let mut xnonce_clone = create_xnonce_from_array([2u8; 24]);
        encrypt_mem_encodable(&mut aead_key_clone, &mut xnonce_clone, &mut test_breaker)
            .expect("Failed to encrypt_serializable(..)")
    };

    let mut x = DecryptionMemZer::new(&mut aead_key, &mut xnonce, &mut ciphertext);

    let result = decrypt_mem_decodable_with::<TestBreaker, _>(&mut x, |_, _| {});

    assert!(result.is_ok());

    // Assert zeroization!
    assert!(x.is_zeroized());
}
