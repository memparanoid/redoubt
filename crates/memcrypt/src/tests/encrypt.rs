// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::{Aead, AeadError};
use memcodec::EncodeError;
use memcodec::support::test_utils::{TestBreaker, TestBreakerBehaviour};
use memzer::ZeroizationProbe;

use crate::encrypt::{EncryptStage, encrypt_encodable_with};
use crate::error::CryptoError;
use crate::guards::EncryptionMemZer;

use super::utils::{create_aead_key, create_nonce};

#[test]
fn test_encrypt_encodable_stage_bytes_required_overflow() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemZer::new(&mut aead_key, &mut nonce, &mut test_breaker);

    let result = encrypt_encodable_with(&mut aead, &mut x, |stage, x| match stage {
        EncryptStage::BytesRequired => {
            x.value
                .set_behaviour(TestBreakerBehaviour::ForceBytesRequiredOverflow);
        }
        EncryptStage::CodecBufLen | EncryptStage::EncodeInto | EncryptStage::Encrypt => {
            unreachable!("Encrypt algorithm will fail at EncryptStage::BytesRequired")
        }
    });

    assert!(result.is_err());
    assert!(matches!(result, Err(CryptoError::Overflow(_))));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_encrypt_encodable_stage_codec_buf_len_overflow() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemZer::new(&mut aead_key, &mut nonce, &mut test_breaker);

    let result = encrypt_encodable_with(&mut aead, &mut x, |stage, x| match stage {
        EncryptStage::BytesRequired => {
            x.value
                .set_behaviour(TestBreakerBehaviour::BytesRequiredReturnMax);
        }
        EncryptStage::CodecBufLen => {}
        EncryptStage::EncodeInto | EncryptStage::Encrypt => {
            unreachable!("Encrypt algorithm will fail at EncryptStage::MemBytesRequired")
        }
    });

    assert!(result.is_err());
    assert!(matches!(result, Err(CryptoError::PlaintextTooLong)));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_encrypt_encodable_stage_encrypt_failure() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemZer::new(&mut aead_key, &mut nonce, &mut test_breaker);

    let result = encrypt_encodable_with(&mut aead, &mut x, |stage, x| match stage {
        EncryptStage::BytesRequired => {}
        EncryptStage::CodecBufLen => {}
        EncryptStage::EncodeInto => {}
        EncryptStage::Encrypt => {
            x.aead_key_size = 12; // Too small for XChacha20Poly1305 & Aegis128L
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
fn test_encrypt_encodable_stage_encode_into_failure() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemZer::new(&mut aead_key, &mut nonce, &mut test_breaker);

    let result = encrypt_encodable_with(&mut aead, &mut x, |stage, x| match stage {
        EncryptStage::BytesRequired => {}
        EncryptStage::CodecBufLen => {}
        EncryptStage::EncodeInto => {
            x.value
                .set_behaviour(TestBreakerBehaviour::ForceEncodeError);
        }
        EncryptStage::Encrypt => {
            unreachable!("Encrypt algorithm will fail at EncryptStage::EncodeInto")
        }
    });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CryptoError::Encode(EncodeError::IntentionalEncodeError))
    ));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_encrypt_encodable_ok() {
    let mut aead = Aead::new();
    let mut aead_key = create_aead_key(&aead, 1);
    let mut nonce = create_nonce(&aead, 2);

    let mut test_breaker = TestBreaker::with_behaviour(TestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemZer::new(&mut aead_key, &mut nonce, &mut test_breaker);
    let result = encrypt_encodable_with(&mut aead, &mut x, |_, _| {});

    assert!(result.is_ok());

    // Assert zeroization!
    assert!(x.is_zeroized());
}
