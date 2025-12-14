// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memaead::AeadApi;
use memaead::support::test_utils::{AeadMock, AeadMockBehaviour};
use memcodec::Codec;
use memcodec::support::test_utils::{CodecTestBreaker, CodecTestBreakerBehaviour};
use redoubt_rand::EntropyError;
use redoubt_util::is_vec_fully_zeroized;
use redoubt_zero::{RedoubtZero, ZeroizationProbe, ZeroizeOnDropSentinel};

use crate::cipherbox::CipherBox;
use crate::error::CipherBoxError;
use crate::helpers::{decrypt_from, encrypt_into};
use crate::master_key::consts::MASTER_KEY_LEN;
use crate::traits::{CipherBoxDyns, DecryptStruct, Decryptable, EncryptStruct, Encryptable};

use super::consts::NUM_FIELDS;

#[derive(Codec, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct CodecTestBreakerBox {
    pub f0: CodecTestBreaker,
    pub f1: CodecTestBreaker,
    pub f2: CodecTestBreaker,
    pub f3: CodecTestBreaker,
    pub f4: CodecTestBreaker,
    pub f5: CodecTestBreaker,
    #[fast_zeroize(skip)]
    #[codec(default)]
    __sentinel: ZeroizeOnDropSentinel,
}

impl Default for CodecTestBreakerBox {
    fn default() -> Self {
        Self {
            f0: CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1 << 0),
            f1: CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1 << 1),
            f2: CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1 << 2),
            f3: CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1 << 3),
            f4: CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1 << 4),
            f5: CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1 << 5),
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }
}

impl CipherBoxDyns<NUM_FIELDS> for CodecTestBreakerBox {
    fn to_decryptable_dyn_fields(&mut self) -> [&mut dyn Decryptable; NUM_FIELDS] {
        [
            &mut self.f0,
            &mut self.f1,
            &mut self.f2,
            &mut self.f3,
            &mut self.f4,
            &mut self.f5,
        ]
    }

    fn to_encryptable_dyn_fields(&mut self) -> [&mut dyn Encryptable; NUM_FIELDS] {
        [
            &mut self.f0,
            &mut self.f1,
            &mut self.f2,
            &mut self.f3,
            &mut self.f4,
            &mut self.f5,
        ]
    }
}

impl<A: AeadApi> EncryptStruct<A, NUM_FIELDS> for CodecTestBreakerBox {
    fn encrypt_into(
        &mut self,
        aead: &mut A,
        aead_key: &[u8],
        nonces: &mut [Vec<u8>; NUM_FIELDS],
        tags: &mut [Vec<u8>; NUM_FIELDS],
    ) -> Result<[Vec<u8>; NUM_FIELDS], CipherBoxError> {
        encrypt_into(
            self.to_encryptable_dyn_fields(),
            aead,
            aead_key,
            nonces,
            tags,
        )
    }
}

impl<A: AeadApi> DecryptStruct<A, NUM_FIELDS> for CodecTestBreakerBox {
    fn decrypt_from(
        &mut self,
        aead: &mut A,
        aead_key: &[u8],
        nonces: &mut [Vec<u8>; NUM_FIELDS],
        tags: &mut [Vec<u8>; NUM_FIELDS],
        ciphertexts: &mut [Vec<u8>; NUM_FIELDS],
    ) -> Result<(), CipherBoxError> {
        decrypt_from(
            &mut self.to_decryptable_dyn_fields(),
            aead,
            aead_key,
            nonces,
            tags,
            ciphertexts,
        )
    }
}

// =============================================================================
// encrypt_struct()
// =============================================================================

#[test]
fn test_encrypt_struct_propagates_encrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    let result = cb.encrypt_struct(&aead_key, &mut value);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

// =============================================================================
// decrypt_struct()
// =============================================================================

#[test]
fn test_decrypt_struct_propagates_encrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailDecryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];

    let result = cb.decrypt_struct(&aead_key);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

// =============================================================================
// maybe_initialize()
// =============================================================================

#[test]
fn test_maybe_initialize_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result = cb.maybe_initialize();

    assert!(cb.assert_healthy().is_err());

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_maybe_initialize_propagates_encrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result = cb.maybe_initialize();

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

// =============================================================================
// decrypt_field()
// =============================================================================

#[test]
fn test_decrypt_field_propagates_decrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailDecryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");
    let mut field = CodecTestBreaker::default();
    let result = cb.decrypt_field::<CodecTestBreaker, 1>(&aead_key, &mut field);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());

    // SAFETY NOTE: There is no need to assert zeroization, if decryption fails CipherBox will remain Poisoned,
    // and no plaintexts on memory.
}

#[test]
fn test_decrypt_field_propagates_decode_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");
    let mut field = CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceDecodeError, 0);
    let result = cb.decrypt_field::<CodecTestBreaker, 1>(&aead_key, &mut field);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());

    // Assert zeroization!
    let tmp = cb.__unsafe_get_tmp_ciphertext();
    assert!(is_vec_fully_zeroized(tmp));
}

#[test]
fn test_decrypt_field_ok() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 0);
    let result = cb.decrypt_field::<CodecTestBreaker, 1>(&aead_key, &mut field);

    assert!(result.is_ok());

    // Assert zeroization!
    let tmp = cb.__unsafe_get_tmp_ciphertext();
    assert!(is_vec_fully_zeroized(tmp));
}

// =============================================================================
// encrypt_field()
// =============================================================================

#[test]
fn test_encrypt_field_propagates_bytes_required_overflow() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceBytesRequiredOverflow, 0);
    let result = cb.encrypt_field::<CodecTestBreaker, 1>(&aead_key, &mut field);

    // SAFETY NOTE:
    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Overflow(_))));
}

#[test]
fn test_encrypt_field_propagates_encode_into_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceEncodeError, 0);
    let result = cb.encrypt_field::<CodecTestBreaker, 1>(&aead_key, &mut field);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());

    // Assert zeroization!
    assert!(cb.__unsafe_get_tmp_codec_buff().is_zeroized());
}

#[test]
fn test_encrypt_field_propagates_entropy_unavailable_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailGenerateNonceAt(NUM_FIELDS));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 0);
    let result = cb.encrypt_field::<CodecTestBreaker, 1>(&aead_key, &mut field);

    // SAFETY NOTE: Box shouldn't be POISONED if entropy is not available (it still can be read).
    assert!(cb.assert_healthy().is_ok());
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CipherBoxError::Entropy(EntropyError::EntropyNotAvailable))
    ));

    // Assert zeroization!
    assert!(cb.__unsafe_get_field_ciphertext::<1>().is_zeroized());
}

#[test]
fn test_encrypt_field_propagates_api_encrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(NUM_FIELDS));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 0);
    let result = cb.encrypt_field::<CodecTestBreaker, 1>(&aead_key, &mut field);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());

    // Assert zeroization!
    assert!(cb.__unsafe_get_field_ciphertext::<1>().is_zeroized());
}

#[test]
fn test_encrypt_field_ok() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100);
    let result = cb.encrypt_field::<CodecTestBreaker, 1>(&aead_key, &mut field);

    assert!(result.is_ok());

    // Assert zeroization!
    assert!(cb.__unsafe_get_tmp_codec_buff().is_zeroized());
    assert!(!cb.__unsafe_get_field_ciphertext::<1>().is_zeroized());
}
// =============================================================================
// open()
// =============================================================================

#[test]
fn test_open_propagates_poison_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 = cb.open(|_| {});
    let result_2 = cb.open(|_| {});

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 = cb.open(|_| {});
    let result_2 = cb.open(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 = cb.open(|_| {});
    let result_2 = cb.open(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_propagates_decrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailDecryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open(|_| {});

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

#[test]
fn test_open_propagates_encrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(NUM_FIELDS));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open(|_| {});

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

// =============================================================================
// open_mut()
// =============================================================================

#[test]
fn test_open_mut_propagates_poison_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 = cb.open_mut(|_| {});
    let result_2 = cb.open_mut(|_| {});

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_mut_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 = cb.open_mut(|_| {});
    let result_2 = cb.open_mut(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_mut_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 = cb.open_mut(|_| {});
    let result_2 = cb.open_mut(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_mut_propagates_decrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailDecryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open_mut(|_| {});

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

#[test]
fn test_open_mut_propagates_encrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(NUM_FIELDS));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open_mut(|_| {});

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

// =============================================================================
// open_field()
// =============================================================================

#[test]
fn test_open_field_propagates_poison_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 = cb.open_field::<CodecTestBreaker, 1, _>(|_| {});
    let result_2 = cb.open_field::<CodecTestBreaker, 1, _>(|_| {});

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 = cb.open_field::<CodecTestBreaker, 1, _>(|_| {});
    let result_2 = cb.open_field::<CodecTestBreaker, 1, _>(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 = cb.open_field::<CodecTestBreaker, 1, _>(|_| {});
    let result_2 = cb.open_field::<CodecTestBreaker, 1, _>(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_propagates_decrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailDecryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result_1 = cb.open_field::<CodecTestBreaker, 1, _>(|_| {});
    let result_2 = cb.open_field::<CodecTestBreaker, 1, _>(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

// =============================================================================
// open_field_mut()
// =============================================================================

#[test]
fn test_open_field_mut_propagates_poison_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 = cb.open_field_mut::<CodecTestBreaker, 1, _>(|_| {});
    let result_2 = cb.open_field_mut::<CodecTestBreaker, 1, _>(|_| {});

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_mut_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 = cb.open_field_mut::<CodecTestBreaker, 1, _>(|_| {});
    let result_2 = cb.open_field_mut::<CodecTestBreaker, 1, _>(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_mut_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 = cb.open_field_mut::<CodecTestBreaker, 1, _>(|_| {});
    let result_2 = cb.open_field_mut::<CodecTestBreaker, 1, _>(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_mut_propagates_decrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailDecryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result_1 = cb.open_field_mut::<CodecTestBreaker, 1, _>(|_| {});
    let result_2 = cb.open_field_mut::<CodecTestBreaker, 1, _>(|_| {});

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_mut_propagates_encrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(NUM_FIELDS));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open_field_mut::<CodecTestBreaker, 1, _>(|_| {});

    assert!(cb.assert_healthy().is_err());
    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
}

// =============================================================================
// leak_field()
// =============================================================================

#[test]
fn test_leak_field_propagates_poison_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = CodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 = cb.leak_field::<CodecTestBreaker, 1>();
    let result_2 = cb.leak_field::<CodecTestBreaker, 1>();

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_leak_field_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailEncryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 = cb.leak_field::<CodecTestBreaker, 1>();
    let result_2 = cb.leak_field::<CodecTestBreaker, 1>();

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_leak_field_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 = cb.leak_field::<CodecTestBreaker, 1>();
    let result_2 = cb.leak_field::<CodecTestBreaker, 1>();

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_leak_field_propagates_decrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailDecryptAt(0));
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result_1 = cb.leak_field::<CodecTestBreaker, 1>();
    let result_2 = cb.leak_field::<CodecTestBreaker, 1>();

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

// =============================================================================
// HAPPY PATH TEST
// =============================================================================
#[test]
fn test_cipherbox_happy_path_test() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<CodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    cb.open(|tb_box| {
        assert_eq!(tb_box.f0.usize.data, 1);
        assert_eq!(tb_box.f1.usize.data, 2);
        assert_eq!(tb_box.f2.usize.data, 4);
        assert_eq!(tb_box.f3.usize.data, 8);
        assert_eq!(tb_box.f4.usize.data, 16);
        assert_eq!(tb_box.f5.usize.data, 32);
    })
    .expect("Failed to open(..)");

    cb.open_mut(|tb_box| {
        tb_box.f0.usize.data <<= 2;
        tb_box.f1.usize.data <<= 2;
        tb_box.f2.usize.data <<= 2;
        tb_box.f3.usize.data <<= 2;
        tb_box.f4.usize.data <<= 2;
        tb_box.f5.usize.data <<= 2;
    })
    .expect("Failed to open_mut(..)");

    cb.open(|tb_box| {
        assert_eq!(tb_box.f0.usize.data, 4);
        assert_eq!(tb_box.f1.usize.data, 8);
        assert_eq!(tb_box.f2.usize.data, 16);
        assert_eq!(tb_box.f3.usize.data, 32);
        assert_eq!(tb_box.f4.usize.data, 64);
        assert_eq!(tb_box.f5.usize.data, 128);
    })
    .expect("Failed to open(..)");

    cb.open_field::<CodecTestBreaker, 0, _>(|tb| {
        assert_eq!(tb.usize.data, 4);
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<CodecTestBreaker, 1, _>(|tb| {
        assert_eq!(tb.usize.data, 8);
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<CodecTestBreaker, 2, _>(|tb| {
        assert_eq!(tb.usize.data, 16);
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<CodecTestBreaker, 3, _>(|tb| {
        assert_eq!(tb.usize.data, 32);
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<CodecTestBreaker, 4, _>(|tb| {
        assert_eq!(tb.usize.data, 64);
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<CodecTestBreaker, 5, _>(|tb| {
        assert_eq!(tb.usize.data, 128);
    })
    .expect("Failed to open_field(..)");

    cb.open_field_mut::<CodecTestBreaker, 0, _>(|tb| {
        println!(
            "Changing field 0: {:?}, {:?}",
            tb.usize.data,
            tb.usize.data << 2
        );
        tb.usize.data <<= 2;
        println!("Field 0 has changed: {:?}", tb.usize.data);
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<CodecTestBreaker, 1, _>(|tb| {
        tb.usize.data <<= 2;
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<CodecTestBreaker, 2, _>(|tb| {
        tb.usize.data <<= 2;
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<CodecTestBreaker, 3, _>(|tb| {
        tb.usize.data <<= 2;
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<CodecTestBreaker, 4, _>(|tb| {
        tb.usize.data <<= 2;
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<CodecTestBreaker, 5, _>(|tb| {
        tb.usize.data <<= 2;
    })
    .expect("Failed to open_field_mut(..)");

    let data_0 = cb
        .leak_field::<CodecTestBreaker, 0>()
        .expect("Failed to leak_field()");
    let data_1 = cb
        .leak_field::<CodecTestBreaker, 1>()
        .expect("Failed to leak_field()");
    let data_2 = cb
        .leak_field::<CodecTestBreaker, 2>()
        .expect("Failed to leak_field()");
    let data_3 = cb
        .leak_field::<CodecTestBreaker, 3>()
        .expect("Failed to leak_field()");
    let data_4 = cb
        .leak_field::<CodecTestBreaker, 4>()
        .expect("Failed to leak_field()");
    let data_5 = cb
        .leak_field::<CodecTestBreaker, 5>()
        .expect("Failed to leak_field()");

    assert_eq!(data_0.usize.data, 16);
    assert_eq!(data_1.usize.data, 32);
    assert_eq!(data_2.usize.data, 64);
    assert_eq!(data_3.usize.data, 128);
    assert_eq!(data_4.usize.data, 256);
    assert_eq!(data_5.usize.data, 512);
}
