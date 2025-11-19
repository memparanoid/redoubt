// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memcode::MemEncodeError;
use memguard::ZeroizationProbe;

use crate::aead_key::AeadKey;
use crate::encrypt::{EncryptStage, encrypt_mem_encodable_with};
use crate::error::CryptoError;
use crate::guards::EncryptionMemGuard;
use crate::xnonce::XNonce;

use super::support::{MemCodeTestBreaker, MemCodeTestBreakerBehaviour};

#[test]
fn test_encrypt_mem_encodable_stage_mem_bytes_required_failure() {
    let mut aead_key = AeadKey::from([1u8; 32]);
    let mut xnonce = XNonce::from([2u8; 24]);
    let mut test_breaker = MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemGuard::new(&mut aead_key, &mut xnonce, &mut test_breaker);

    let result = encrypt_mem_encodable_with(&mut x, |stage, x| match stage {
        EncryptStage::MemBytesRequired => {
            x.value
                .change_behaviour(MemCodeTestBreakerBehaviour::ForceBytesRequiredUsizeMax);
        }
        EncryptStage::DrainInto
        | EncryptStage::AeadBufferFillWithPlaintext
        | EncryptStage::Encrypt => {
            unreachable!("Encrypt algorithm will fail at EncryptStage::MemBytesRequired")
        }
    });

    assert!(result.is_err());
    assert!(matches!(result, Err(CryptoError::Overflow(_))));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_encrypt_mem_encodable_stage_drain_into_failure() {
    let mut aead_key = AeadKey::from([1u8; 32]);
    let mut xnonce = XNonce::from([2u8; 24]);
    let mut test_breaker = MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemGuard::new(&mut aead_key, &mut xnonce, &mut test_breaker);

    let result = encrypt_mem_encodable_with(&mut x, |stage, x| match stage {
        EncryptStage::MemBytesRequired => {}
        EncryptStage::DrainInto => {
            x.value
                .change_behaviour(MemCodeTestBreakerBehaviour::ForceEncodeError);
        }
        EncryptStage::AeadBufferFillWithPlaintext | EncryptStage::Encrypt => {
            unreachable!("Encrypt algorithm will fail at EncryptStage::DrainInto")
        }
    });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CryptoError::MemEncode(
            MemEncodeError::IntentionalEncodeError
        ))
    ));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_encrypt_mem_encodable_stage_aead_buffer_fill_with_plaintext_failure() {
    let mut aead_key = AeadKey::from([1u8; 32]);
    let mut xnonce = XNonce::from([2u8; 24]);
    let mut test_breaker = MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemGuard::new(&mut aead_key, &mut xnonce, &mut test_breaker);

    let result = encrypt_mem_encodable_with(&mut x, |stage, x| match stage {
        EncryptStage::MemBytesRequired => {}
        EncryptStage::DrainInto => {}
        EncryptStage::AeadBufferFillWithPlaintext => {
            x.aead_buffer
                .zeroized_reserve_exact(3)
                .expect("Failed to zeroized_reserve_exact()");
            x.aead_buffer
                .drain_slice(&mut [1, 2, 3])
                .expect("Failed to drain_slice()");
        }
        EncryptStage::Encrypt => {
            unreachable!("Encrypt algorithm will fail at EncryptStage::DrainInto")
        }
    });

    assert!(result.is_err());
    assert!(matches!(result, Err(CryptoError::AeadBufferNotZeroized)));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_encrypt_mem_encodable_stage_encrypt_failure() {
    let mut aead_key = AeadKey::from([1u8; 32]);
    let mut xnonce = XNonce::from([2u8; 24]);
    let mut test_breaker = MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemGuard::new(&mut aead_key, &mut xnonce, &mut test_breaker);

    let result = encrypt_mem_encodable_with(&mut x, |stage, x| match stage {
        EncryptStage::MemBytesRequired => {}
        EncryptStage::DrainInto => {}
        EncryptStage::AeadBufferFillWithPlaintext => {}
        EncryptStage::Encrypt => {
            x.aead_key_size = 16;
        }
    });

    assert!(result.is_err());
    assert!(matches!(result, Err(CryptoError::InvalidKeyLength)));

    // Assert zeroization!
    assert!(x.is_zeroized());
}

#[test]
fn test_encrypt_mem_encodable_ok() {
    let mut aead_key = AeadKey::from([1u8; 32]);
    let mut xnonce = XNonce::from([2u8; 24]);
    let mut test_breaker = MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None);

    // Assert (not) zeroization!
    assert!(!test_breaker.is_zeroized());

    let mut x = EncryptionMemGuard::new(&mut aead_key, &mut xnonce, &mut test_breaker);
    let result = encrypt_mem_encodable_with(&mut x, |_, _| {});

    assert!(result.is_ok());

    // Assert zeroization!
    assert!(x.is_zeroized());
}
