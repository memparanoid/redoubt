// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_aead::AeadApi;
use redoubt_aead::support::test_utils::{AeadMock, AeadMockBehaviour};
use redoubt_alloc::RedoubtVec;
use redoubt_codec::RedoubtCodec;
use redoubt_codec::support::test_utils::{
    RedoubtCodecTestBreaker, RedoubtCodecTestBreakerBehaviour,
};
use redoubt_rand::EntropyError;
use redoubt_util::is_vec_fully_zeroized;
use redoubt_zero::{RedoubtZero, ZeroizationProbe, ZeroizeOnDropSentinel, ZeroizingGuard};

use crate::cipherbox::CipherBox;
use crate::error::CipherBoxError;
use crate::helpers::{decrypt_from, encrypt_into};
use crate::master_key::consts::MASTER_KEY_LEN;
use crate::traits::{CipherBoxDyns, DecryptStruct, Decryptable, EncryptStruct, Encryptable};

use super::consts::NUM_FIELDS;

#[derive(RedoubtCodec, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct RedoubtCodecTestBreakerBox {
    pub f0: RedoubtCodecTestBreaker,
    pub f1: RedoubtCodecTestBreaker,
    pub f2: RedoubtCodecTestBreaker,
    pub f3: RedoubtCodecTestBreaker,
    pub f4: RedoubtCodecTestBreaker,
    pub f5: RedoubtCodecTestBreaker,
    #[fast_zeroize(skip)]
    #[codec(default)]
    __sentinel: ZeroizeOnDropSentinel,
}

impl Default for RedoubtCodecTestBreakerBox {
    fn default() -> Self {
        Self {
            f0: RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 1 << 0),
            f1: RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 1 << 1),
            f2: RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 1 << 2),
            f3: RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 1 << 3),
            f4: RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 1 << 4),
            f5: RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 1 << 5),
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }
}

impl CipherBoxDyns<NUM_FIELDS> for RedoubtCodecTestBreakerBox {
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

impl<A: AeadApi> EncryptStruct<A, NUM_FIELDS> for RedoubtCodecTestBreakerBox {
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

impl<A: AeadApi> DecryptStruct<A, NUM_FIELDS> for RedoubtCodecTestBreakerBox {
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

// Stress test CipherBox with single RedoubtVec field
#[derive(RedoubtCodec, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct RedoubtVecBox {
    pub vec: RedoubtVec<RedoubtCodecTestBreaker>,
    #[codec(default)]
    __sentinel: ZeroizeOnDropSentinel,
}

impl Default for RedoubtVecBox {
    fn default() -> Self {
        Self {
            vec: RedoubtVec::new(),
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }
}

impl CipherBoxDyns<1> for RedoubtVecBox {
    fn to_decryptable_dyn_fields(&mut self) -> [&mut dyn Decryptable; 1] {
        [&mut self.vec]
    }

    fn to_encryptable_dyn_fields(&mut self) -> [&mut dyn Encryptable; 1] {
        [&mut self.vec]
    }
}

impl<A: AeadApi> EncryptStruct<A, 1> for RedoubtVecBox {
    fn encrypt_into(
        &mut self,
        aead: &mut A,
        aead_key: &[u8],
        nonces: &mut [Vec<u8>; 1],
        tags: &mut [Vec<u8>; 1],
    ) -> Result<[Vec<u8>; 1], CipherBoxError> {
        encrypt_into(
            self.to_encryptable_dyn_fields(),
            aead,
            aead_key,
            nonces,
            tags,
        )
    }
}

impl<A: AeadApi> DecryptStruct<A, 1> for RedoubtVecBox {
    fn decrypt_from(
        &mut self,
        aead: &mut A,
        aead_key: &[u8],
        nonces: &mut [Vec<u8>; 1],
        tags: &mut [Vec<u8>; 1],
        ciphertexts: &mut [Vec<u8>; 1],
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
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

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
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthDecrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
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
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result = cb.maybe_initialize();

    assert!(cb.assert_healthy().is_err());

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_maybe_initialize_propagates_encrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

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
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthDecrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");
    let mut field = RedoubtCodecTestBreaker::default();
    let result = cb.decrypt_field::<RedoubtCodecTestBreaker, 1>(&aead_key, &mut field);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());

    // SAFETY NOTE: There is no need to assert zeroization, if decryption fails CipherBox will remain Poisoned,
    // and no plaintexts on memory.
}

#[test]
fn test_decrypt_field_propagates_decode_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");
    let mut field =
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceDecodeError, 0);
    let result = cb.decrypt_field::<RedoubtCodecTestBreaker, 1>(&aead_key, &mut field);

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
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 0);
    let result = cb.decrypt_field::<RedoubtCodecTestBreaker, 1>(&aead_key, &mut field);

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
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
        0,
    );
    let result = cb.encrypt_field::<RedoubtCodecTestBreaker, 1>(&aead_key, &mut field);

    // SAFETY NOTE:
    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Overflow(_))));
}

#[test]
fn test_encrypt_field_propagates_encode_into_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field =
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceEncodeError, 0);
    let result = cb.encrypt_field::<RedoubtCodecTestBreaker, 1>(&aead_key, &mut field);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());

    // Assert zeroization!
    assert!(cb.__unsafe_get_tmp_codec_buff().is_zeroized());
}

#[test]
fn test_encrypt_field_propagates_entropy_unavailable_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthGenerateNonce(NUM_FIELDS + 1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 0);
    let result = cb.encrypt_field::<RedoubtCodecTestBreaker, 1>(&aead_key, &mut field);

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
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(NUM_FIELDS + 1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 0);
    let result = cb.encrypt_field::<RedoubtCodecTestBreaker, 1>(&aead_key, &mut field);

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());

    // Assert zeroization!
    assert!(cb.__unsafe_get_field_ciphertext::<1>().is_zeroized());
}

#[test]
fn test_encrypt_field_ok() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    cb.encrypt_struct(&aead_key, &mut value)
        .expect("Failed to encrypt_struct(..)");

    let mut field = RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, 100);
    let result = cb.encrypt_field::<RedoubtCodecTestBreaker, 1>(&aead_key, &mut field);

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
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 = cb.open::<_, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 = cb.open::<_, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 = cb.open::<_, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_propagates_decrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthDecrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

#[test]
fn test_open_propagates_encrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(NUM_FIELDS + 1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

#[test]
fn test_open_infers_result_type() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open::<_, _, CipherBoxError>(|test_breaker_box| {
        Ok(test_breaker_box.f0.usize.data + test_breaker_box.f1.usize.data)
    });

    assert!(result.is_ok());
    assert_eq!(*result.unwrap(), 3);
}

#[test]
fn test_open_when_callback_error_is_propagated_cipherbox_is_not_poisoned() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    // Callback returns error
    let result: Result<ZeroizingGuard<()>, CipherBoxError> =
        cb.open(|_| Err(CipherBoxError::IntentionalCipherBoxError));

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CipherBoxError::IntentionalCipherBoxError)
    ));

    // CipherBox should NOT be poisoned
    assert!(cb.assert_healthy().is_ok());

    // Should be able to use CipherBox again
    let current_f0_value = cb.open::<_, _, CipherBoxError>(|tb| Ok(tb.f0.usize.data));

    assert!(current_f0_value.is_ok());
    assert_eq!(*current_f0_value.unwrap(), 1);
}

// =============================================================================
// open_mut()
// =============================================================================

#[test]
fn test_open_mut_propagates_poison_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 = cb.open_mut::<_, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open_mut::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_mut_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 = cb.open_mut::<_, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open_mut::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_mut_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 = cb.open_mut::<_, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open_mut::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_mut_propagates_decrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthDecrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open_mut::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

#[test]
fn test_open_mut_propagates_encrypt_struct_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(NUM_FIELDS + 1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open_mut::<_, _, CipherBoxError>(|_| Ok(()));

    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(cb.assert_healthy().is_err());
}

#[test]
fn test_open_mut_infers_result_type() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open_mut::<_, _, CipherBoxError>(|test_breaker_box| {
        test_breaker_box.f0.usize.data += 10;
        Ok(test_breaker_box.f0.usize.data)
    });

    assert!(result.is_ok());
    assert_eq!(*result.unwrap(), 11);
}

#[test]
fn test_open_mut_when_callback_error_is_propagated_cipherbox_is_not_poisoned() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    // Callback returns error after modifying data
    let result: Result<ZeroizingGuard<()>, CipherBoxError> =
        cb.open_mut(|test_breaker_box| {
            test_breaker_box.f0.usize.data = 999;
            Err(CipherBoxError::IntentionalCipherBoxError)
        });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CipherBoxError::IntentionalCipherBoxError)
    ));

    // CipherBox should NOT be poisoned
    assert!(cb.assert_healthy().is_ok());

    // Should be able to use CipherBox again and data should be unchanged (rollback)
    let current_f0_value = cb.open::<_, _, CipherBoxError>(|tb| Ok(tb.f0.usize.data));

    assert!(current_f0_value.is_ok());
    assert_eq!(*current_f0_value.unwrap(), 1);
}

#[test]
fn test_open_mut_zeroizes_tmp_ciphertexts_on_callback_failure() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    // Callback fails
    let result: Result<ZeroizingGuard<()>, CipherBoxError> =
        cb.open_mut(|_| Err(CipherBoxError::IntentionalCipherBoxError));

    assert!(result.is_err());

    // Verify tmp_ciphertexts are zeroized
    let tmp_ciphertexts = cb.__unsafe_get_tmp_ciphertexts();
    assert!(tmp_ciphertexts.is_zeroized());
}

// =============================================================================
// open_field()
// =============================================================================

#[test]
fn test_open_field_propagates_poison_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 = cb.open_field::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open_field::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 = cb.open_field::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open_field::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 = cb.open_field::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open_field::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_propagates_decrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthDecrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result_1 = cb.open_field::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));
    let result_2 = cb.open_field::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_infers_result_type() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open_field::<RedoubtCodecTestBreaker, 0, _, _, CipherBoxError>(|tb| {
        Ok(tb.usize.data + 10)
    });

    assert!(result.is_ok());
    assert_eq!(*result.unwrap(), 11);
}

#[test]
fn test_open_field_when_callback_error_is_propagated_cipherbox_is_not_poisoned() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    // Callback returns error
    let result: Result<ZeroizingGuard<()>, CipherBoxError> =
        cb.open_field::<RedoubtCodecTestBreaker, 0, _, _, _>(|_| {
            Err(CipherBoxError::IntentionalCipherBoxError)
        });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CipherBoxError::IntentionalCipherBoxError)
    ));

    // CipherBox should NOT be poisoned
    assert!(cb.assert_healthy().is_ok());

    // Should be able to use CipherBox again
    let current_f0_value =
        cb.open_field::<RedoubtCodecTestBreaker, 0, _, _, CipherBoxError>(|tb| Ok(tb.usize.data));

    assert!(current_f0_value.is_ok());
    assert_eq!(*current_f0_value.unwrap(), 1);
}

// =============================================================================
// open_field_mut()
// =============================================================================

#[test]
fn test_open_field_mut_propagates_poison_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 =
        cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));
    let result_2 =
        cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_mut_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 =
        cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));
    let result_2 =
        cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_mut_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 =
        cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));
    let result_2 =
        cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_mut_propagates_decrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthDecrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result_1 =
        cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));
    let result_2 =
        cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_mut_propagates_encrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(NUM_FIELDS + 1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|_| Ok(()));

    assert!(cb.assert_healthy().is_err());
    assert!(result.is_err());
    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_open_field_mut_infers_result_type() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result = cb.open_field_mut::<RedoubtCodecTestBreaker, 0, _, _, CipherBoxError>(|tb| {
        tb.usize.data += 10;
        Ok(tb.usize.data)
    });

    assert!(result.is_ok());
    assert_eq!(*result.unwrap(), 11);
}

#[test]
fn test_open_field_mut_when_callback_error_is_propagated_cipherbox_is_not_poisoned() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    // Callback returns error after modifying data
    let result: Result<ZeroizingGuard<()>, CipherBoxError> = cb
        .open_field_mut::<RedoubtCodecTestBreaker, 0, _, _, _>(|tb| {
            tb.usize.data = 999;
            Err(CipherBoxError::IntentionalCipherBoxError)
        });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(CipherBoxError::IntentionalCipherBoxError)
    ));

    // CipherBox should NOT be poisoned
    assert!(cb.assert_healthy().is_ok());

    // Should be able to use CipherBox again and data should be unchanged (rollback)
    let current_f0_value =
        cb.open_field::<RedoubtCodecTestBreaker, 0, _, _, CipherBoxError>(|tb| Ok(tb.usize.data));

    assert!(current_f0_value.is_ok());
    assert_eq!(*current_f0_value.unwrap(), 1);
}

// =============================================================================
// leak_field()
// =============================================================================

#[test]
fn test_leak_field_propagates_poison_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);
    let aead_key = [0u8; AeadMock::KEY_SIZE];
    let mut value = RedoubtCodecTestBreakerBox::default();

    assert!(cb.encrypt_struct(&aead_key, &mut value).is_err());
    assert!(cb.assert_healthy().is_err());

    let result_1 = cb.leak_field::<RedoubtCodecTestBreaker, 1, _>();
    let result_2 = cb.leak_field::<RedoubtCodecTestBreaker, 1, _>();

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_leak_field_propagates_initialization_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthEncrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    let result_1 = cb.leak_field::<RedoubtCodecTestBreaker, 1, _>();
    let result_2 = cb.leak_field::<RedoubtCodecTestBreaker, 1, _>();

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_leak_field_propagates_leak_master_key_error() {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    cb.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result_1 = cb.leak_field::<RedoubtCodecTestBreaker, 1, _>();
    let result_2 = cb.leak_field::<RedoubtCodecTestBreaker, 1, _>();

    assert!(cb.assert_healthy().is_err());

    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(matches!(result_1, Err(CipherBoxError::Poisoned)));
    assert!(matches!(result_2, Err(CipherBoxError::Poisoned)));
}

#[test]
fn test_leak_field_propagates_decrypt_error() {
    let aead = AeadMock::new(AeadMockBehaviour::FailAtNthDecrypt(1));
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    assert!(cb.maybe_initialize().is_ok());

    let result_1 = cb.leak_field::<RedoubtCodecTestBreaker, 1, _>();
    let result_2 = cb.leak_field::<RedoubtCodecTestBreaker, 1, _>();

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
    let mut cb = CipherBox::<RedoubtCodecTestBreakerBox, AeadMock, NUM_FIELDS>::new(aead);

    cb.open::<_, _, CipherBoxError>(|tb_box| {
        assert_eq!(tb_box.f0.usize.data, 1);
        assert_eq!(tb_box.f1.usize.data, 2);
        assert_eq!(tb_box.f2.usize.data, 4);
        assert_eq!(tb_box.f3.usize.data, 8);
        assert_eq!(tb_box.f4.usize.data, 16);
        assert_eq!(tb_box.f5.usize.data, 32);
        Ok(())
    })
    .expect("Failed to open(..)");

    cb.open_mut::<_, _, CipherBoxError>(|tb_box| {
        tb_box.f0.usize.data <<= 2;
        tb_box.f1.usize.data <<= 2;
        tb_box.f2.usize.data <<= 2;
        tb_box.f3.usize.data <<= 2;
        tb_box.f4.usize.data <<= 2;
        tb_box.f5.usize.data <<= 2;
        Ok(())
    })
    .expect("Failed to open_mut(..)");

    cb.open::<_, _, CipherBoxError>(|tb_box| {
        assert_eq!(tb_box.f0.usize.data, 4);
        assert_eq!(tb_box.f1.usize.data, 8);
        assert_eq!(tb_box.f2.usize.data, 16);
        assert_eq!(tb_box.f3.usize.data, 32);
        assert_eq!(tb_box.f4.usize.data, 64);
        assert_eq!(tb_box.f5.usize.data, 128);
        Ok(())
    })
    .expect("Failed to open(..)");

    cb.open_field::<RedoubtCodecTestBreaker, 0, _, _, CipherBoxError>(|tb| {
        assert_eq!(tb.usize.data, 4);
        Ok(())
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|tb| {
        assert_eq!(tb.usize.data, 8);
        Ok(())
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<RedoubtCodecTestBreaker, 2, _, _, CipherBoxError>(|tb| {
        assert_eq!(tb.usize.data, 16);
        Ok(())
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<RedoubtCodecTestBreaker, 3, _, _, CipherBoxError>(|tb| {
        assert_eq!(tb.usize.data, 32);
        Ok(())
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<RedoubtCodecTestBreaker, 4, _, _, CipherBoxError>(|tb| {
        assert_eq!(tb.usize.data, 64);
        Ok(())
    })
    .expect("Failed to open_field(..)");
    cb.open_field::<RedoubtCodecTestBreaker, 5, _, _, CipherBoxError>(|tb| {
        assert_eq!(tb.usize.data, 128);
        Ok(())
    })
    .expect("Failed to open_field(..)");

    cb.open_field_mut::<RedoubtCodecTestBreaker, 0, _, _, CipherBoxError>(|tb| {
        println!(
            "Changing field 0: {:?}, {:?}",
            tb.usize.data,
            tb.usize.data << 2
        );
        tb.usize.data <<= 2;
        println!("Field 0 has changed: {:?}", tb.usize.data);
        Ok(())
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<RedoubtCodecTestBreaker, 1, _, _, CipherBoxError>(|tb| {
        tb.usize.data <<= 2;
        Ok(())
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<RedoubtCodecTestBreaker, 2, _, _, CipherBoxError>(|tb| {
        tb.usize.data <<= 2;
        Ok(())
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<RedoubtCodecTestBreaker, 3, _, _, CipherBoxError>(|tb| {
        tb.usize.data <<= 2;
        Ok(())
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<RedoubtCodecTestBreaker, 4, _, _, CipherBoxError>(|tb| {
        tb.usize.data <<= 2;
        Ok(())
    })
    .expect("Failed to open_field_mut(..)");
    cb.open_field_mut::<RedoubtCodecTestBreaker, 5, _, _, CipherBoxError>(|tb| {
        tb.usize.data <<= 2;
        Ok(())
    })
    .expect("Failed to open_field_mut(..)");

    let data_0 = cb
        .leak_field::<RedoubtCodecTestBreaker, 0, CipherBoxError>()
        .expect("Failed to leak_field()");
    let data_1 = cb
        .leak_field::<RedoubtCodecTestBreaker, 1, CipherBoxError>()
        .expect("Failed to leak_field()");
    let data_2 = cb
        .leak_field::<RedoubtCodecTestBreaker, 2, CipherBoxError>()
        .expect("Failed to leak_field()");
    let data_3 = cb
        .leak_field::<RedoubtCodecTestBreaker, 3, CipherBoxError>()
        .expect("Failed to leak_field()");
    let data_4 = cb
        .leak_field::<RedoubtCodecTestBreaker, 4, CipherBoxError>()
        .expect("Failed to leak_field()");
    let data_5 = cb
        .leak_field::<RedoubtCodecTestBreaker, 5, CipherBoxError>()
        .expect("Failed to leak_field()");

    assert_eq!(data_0.usize.data, 16);
    assert_eq!(data_1.usize.data, 32);
    assert_eq!(data_2.usize.data, 64);
    assert_eq!(data_3.usize.data, 128);
    assert_eq!(data_4.usize.data, 256);
    assert_eq!(data_5.usize.data, 512);
}

// =============================================================================
// Stress Tests
// =============================================================================

fn stress_test_redoubt_vec_grow_shrink_cycles(size: usize) {
    let aead = AeadMock::new(AeadMockBehaviour::None);
    let mut cb = CipherBox::<RedoubtVecBox, AeadMock, 1>::new(aead);

    // Create original data
    let original: Vec<RedoubtCodecTestBreaker> = (0..size)
        .map(|i| RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::None, i))
        .collect();

    // Phase 1: Grow acumulativo (0, 1, 2, ..., size)
    let mut accumulated: Vec<RedoubtCodecTestBreaker> = Vec::new();

    for i in 0..=size {
        cb.open_mut::<_, _, CipherBoxError>(|vault| {
            let mut src = original[0..i].to_vec();
            vault.vec.extend_from_mut_slice(&mut src);
            Ok(())
        })
        .expect("Failed open_mut during grow phase");

        // Update expected accumulated
        accumulated.extend_from_slice(&original[0..i]);
        let expected_len = (i * (i + 1)) / 2;

        cb.open::<_, _, CipherBoxError>(|vault| {
            assert_eq!(
                vault.vec.as_slice().len(),
                expected_len,
                "Grow phase len mismatch at i={}",
                i
            );
            assert_eq!(
                vault.vec.as_slice(),
                &accumulated,
                "Grow phase content mismatch at i={}",
                i
            );
            Ok(())
        })
        .expect("Failed open during grow verify");
    }

    // Clear after grow phase
    cb.open_mut::<_, _, CipherBoxError>(|vault| {
        vault.vec.clear();
        Ok(())
    })
    .expect("Failed to open_mut(..)");

    cb.open::<_, _, CipherBoxError>(|vault| {
        assert_eq!(vault.vec.len(), 0);
        Ok(())
    })
    .expect("Failed to open(..)");

    // Phase 2: Grow acumulativo reversed (size, size-1, ..., 1, 0)
    let mut accumulated: Vec<RedoubtCodecTestBreaker> = Vec::new();

    for i in (0..=size).rev() {
        cb.open_mut::<_, _, CipherBoxError>(|vault| {
            let mut src = original[0..i].to_vec();
            vault.vec.extend_from_mut_slice(&mut src);
            Ok(())
        })
        .expect("Failed open_mut during shrink phase");

        // Update expected accumulated
        accumulated.extend_from_slice(&original[0..i]);
        let expected_len = (size - i + 1) * (size + i) / 2;

        cb.open::<_, _, CipherBoxError>(|vault| {
            assert_eq!(
                vault.vec.as_slice().len(),
                expected_len,
                "Shrink phase len mismatch at i={}",
                i
            );
            assert_eq!(
                vault.vec.as_slice(),
                &accumulated,
                "Shrink phase content mismatch at i={}",
                i
            );
            Ok(())
        })
        .expect("Failed open during shrink verify");
    }
}

#[test]
fn stress_test_redoubt_vec_grow_shrink_cycles_small() {
    stress_test_redoubt_vec_grow_shrink_cycles(10);
}

#[test]
fn stress_test_redoubt_vec_grow_shrink_cycles_medium() {
    stress_test_redoubt_vec_grow_shrink_cycles(20);
}

#[test]
fn stress_test_redoubt_vec_grow_shrink_cycles_large() {
    stress_test_redoubt_vec_grow_shrink_cycles(30);
}
