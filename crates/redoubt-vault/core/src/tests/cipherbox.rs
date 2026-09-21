// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_aead::{Aead, AeadBehaviour, AeadError};
use redoubt_codec::RedoubtCodec;
use redoubt_codec::support::test_utils::{
    RedoubtCodecTestBreaker, RedoubtCodecTestBreakerBehaviour,
};
use redoubt_zero::{
    AssertZeroizeOnDrop, FastZeroizable, RedoubtZero, ZeroizationProbe, ZeroizeOnDropSentinel,
    ZeroizingGuard,
};

use crate::cipherbox::CipherBox;
use crate::error::CipherBoxError;
use crate::helpers::{decrypt_from, encrypt_into};
use crate::master_key::consts::MASTER_KEY_LEN;
use crate::master_key::leak_master_key;
use crate::traits::{CipherBoxDyns, DecryptStruct, Decryptable, EncryptStruct, Encryptable};
use crate::types::{Data, DataBuffers};

use super::consts::NUM_FIELDS;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(RedoubtCodec, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct TestBox {
    pub f0: RedoubtCodecTestBreaker,
    pub f1: RedoubtCodecTestBreaker,
    pub f2: RedoubtCodecTestBreaker,
    pub f3: RedoubtCodecTestBreaker,
    pub f4: RedoubtCodecTestBreaker,
    pub f5: RedoubtCodecTestBreaker,
    #[codec(default)]
    __sentinel: ZeroizeOnDropSentinel,
}

impl Default for TestBox {
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

impl CipherBoxDyns<NUM_FIELDS> for TestBox {
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

impl EncryptStruct<NUM_FIELDS> for TestBox {
    fn encrypt_into(
        &mut self,
        aead: &mut Aead,
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

impl DecryptStruct<NUM_FIELDS> for TestBox {
    fn decrypt_from(
        &mut self,
        aead: &Aead,
        aead_key: &[u8],
        nonces: &[Vec<u8>; NUM_FIELDS],
        tags: &[Vec<u8>; NUM_FIELDS],
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

/// The key a box seals itself with, which is the only one an open reaches
/// for.
///
/// A test that seals with any other key builds a box that cannot be opened
/// through `open_value`: the tag is the one that other key wrote, so the read
/// fails to authenticate and poisons the box instead of returning what was
/// put in it.
///
/// Not a constant: `Aead::default()` picks AEGIS where the hardware has AES
/// and XChaCha20-Poly1305 where it does not, and those take keys of different
/// widths.
fn master_key() -> Result<ZeroizingGuard<Vec<u8>>, BoxError> {
    Ok(leak_master_key(Aead::default().key_size())?)
}

/// A box with every field sealed, which is the state a read has something to
/// open in.
///
/// A behaviour that counts decrypts still lets this seal go through, so the
/// injected failure lands on the read the test is about.
fn sealed(aead: Aead) -> Result<CipherBox<TestBox, NUM_FIELDS>, BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(aead);

    boxed.maybe_initialize()?;

    Ok(boxed)
}

// ============================================================================
// Shared reads
// ============================================================================

fn assert_sync<T: Sync>() {}
fn assert_send<T: Send>() {}

/// A read takes the box by shared reference so that several threads can hold
/// one box and open it at once, which they can only do if it is `Sync`.
///
/// Nothing declares that: it holds because every field the box carries is
/// plain data or an atomic. A `Cell` in any of them takes it away, and the
/// consumer that can no longer share its box is where that would otherwise
/// be found.
#[test]
fn test_a_box_can_be_read_from_several_threads() {
    assert_sync::<CipherBox<TestBox, NUM_FIELDS>>();
    assert_send::<CipherBox<TestBox, NUM_FIELDS>>();
}

// ============================================================================
// Zeroization
// ============================================================================

// No `is_zeroizable` test here on purpose: at rest a CipherBox holds only
// ciphertext, nonces and tags, and zeroizing a live box is not a real
// operation — it just poisons decryption. What matters is that the buffers a
// plaintext passes through are wiped after every operation, asserted per
// operation below, and that everything is wiped on drop.

#[test]
fn test_cipher_box_zeroizes_on_drop() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.unzeroize();
    assert!(!boxed.is_zeroized());

    boxed.assert_zeroize_on_drop();

    Ok(())
}

// ============================================================================
// new
// ============================================================================

#[test]
fn test_new_returns_a_healthy_box() {
    let boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    assert!(boxed.assert_healthy().is_ok());
}

/// Nothing has sealed it, which is the state a read answers with the default
/// instead of opening anything.
#[test]
fn test_new_returns_a_box_holding_no_ciphertexts() {
    let boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    assert!(boxed.__unsafe_get_ciphertexts().iter().all(Vec::is_empty));
}

// ============================================================================
// assert_healthy
// ============================================================================

#[test]
fn test_assert_healthy_reports_zeroized_once_the_box_is_wiped() {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    boxed.fast_zeroize();

    assert!(matches!(
        boxed.assert_healthy(),
        Err(CipherBoxError::Zeroized)
    ));
}

#[test]
fn test_assert_healthy_reports_poisoned_once_an_operation_has_failed() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(1));
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(aead);

    assert!(
        boxed
            .encrypt_struct(&master_key()?, &mut TestBox::default())
            .is_err()
    );

    assert!(matches!(
        boxed.assert_healthy(),
        Err(CipherBoxError::Poisoned)
    ));

    Ok(())
}

#[test]
fn test_assert_healthy_returns_ok_on_a_fresh_box() {
    let boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    assert!(boxed.assert_healthy().is_ok());
}

// ============================================================================
// encrypt_struct
// ============================================================================

#[test]
fn test_encrypt_struct_poisons_on_a_failed_seal() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(1));
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(aead);

    let result = boxed.encrypt_struct(&master_key()?, &mut TestBox::default());

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

/// Sealing every field at once is what leaves a box initialized, and a read
/// opens what is there instead of answering with the default.
#[test]
fn test_encrypt_struct_leaves_every_field_sealed() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    boxed.encrypt_struct(&master_key()?, &mut TestBox::default())?;

    assert!(
        boxed
            .__unsafe_get_ciphertexts()
            .iter()
            .all(|it| !it.is_empty())
    );

    Ok(())
}

// ============================================================================
// decrypt_struct
// ============================================================================

#[test]
fn test_decrypt_struct_poisons_on_a_failed_open() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;

    let result = boxed.decrypt_struct(&master_key()?);

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

/// What the AEAD drains is a clone, so the box can be opened a second time.
#[test]
fn test_decrypt_struct_leaves_the_sealed_fields_intact() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let before = boxed.__unsafe_get_ciphertexts().clone();

    boxed.decrypt_struct(&master_key()?)?;

    assert_eq!(boxed.__unsafe_get_ciphertexts(), &before);

    Ok(())
}

// ============================================================================
// decrypt_struct_from
// ============================================================================

/// A caller that keeps the buffers it lent holds no plaintext, and the
/// decoder draining them as it reads is what leaves them that way.
#[test]
fn test_decrypt_struct_from_leaves_the_lent_buffers_zeroized() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let mut data: DataBuffers<NUM_FIELDS> = boxed.__unsafe_get_ciphertexts().clone();

    boxed.decrypt_struct_from(&master_key()?, &mut data)?;

    assert!(data.is_zeroized());

    Ok(())
}

#[test]
fn test_decrypt_struct_from_leaves_the_lent_buffers_zeroized_on_a_failed_open()
-> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;
    let mut data: DataBuffers<NUM_FIELDS> = boxed.__unsafe_get_ciphertexts().clone();

    assert!(
        boxed
            .decrypt_struct_from(&master_key()?, &mut data)
            .is_err()
    );

    assert!(data.is_zeroized());

    Ok(())
}

// ============================================================================
// maybe_initialize
// ============================================================================

/// The key never came back, so nothing was sealed and nothing was written
/// over. A box that is intact is not poisoned.
#[test]
fn test_maybe_initialize_propagates_leak_master_key_error() {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    boxed.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    assert!(matches!(
        boxed.maybe_initialize(),
        Err(CipherBoxError::Buffer(_))
    ));
    assert!(boxed.assert_healthy().is_ok());
}

#[test]
fn test_maybe_initialize_propagates_encrypt_struct_error() {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(1));
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(aead);

    assert!(matches!(
        boxed.maybe_initialize(),
        Err(CipherBoxError::Poisoned)
    ));
    assert!(boxed.assert_healthy().is_err());
}

/// The second call asks the master key for nothing and seals nothing, which
/// is what the ciphertexts standing still says.
#[test]
fn test_maybe_initialize_returns_ok_leaving_a_sealed_box_as_it_was() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;
    let before = boxed.__unsafe_get_ciphertexts().clone();

    boxed.maybe_initialize()?;

    assert_eq!(boxed.__unsafe_get_ciphertexts(), &before);

    Ok(())
}

#[test]
fn test_maybe_initialize_seals_every_field_of_an_unsealed_box() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    boxed.maybe_initialize()?;

    assert!(
        boxed
            .__unsafe_get_ciphertexts()
            .iter()
            .all(|it| !it.is_empty())
    );

    Ok(())
}

// ============================================================================
// try_decrypt_field
// ============================================================================

#[test]
fn test_try_decrypt_field_propagates_decrypt_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;
    let mut field = RedoubtCodecTestBreaker::default();
    let mut data = Data::default();

    let result = boxed.try_decrypt_field::<_, 1>(&master_key()?, &mut field, &mut data);

    assert!(matches!(result, Err(CipherBoxError::Aead(_))));

    Ok(())
}

#[test]
fn test_try_decrypt_field_propagates_decode_error() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let mut field =
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceDecodeError, 0);
    let mut data = Data::default();

    let result = boxed.try_decrypt_field::<_, 1>(&master_key()?, &mut field, &mut data);

    assert!(matches!(result, Err(CipherBoxError::Decode(_))));

    Ok(())
}

/// Nothing here wipes the buffer, so what leaves it in zeros is the decoder
/// draining each range as it reads it.
#[test]
fn test_try_decrypt_field_leaves_the_lent_buffer_zeroized() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let mut field = RedoubtCodecTestBreaker::default();
    let mut data = Data::default();

    boxed.try_decrypt_field::<_, 1>(&master_key()?, &mut field, &mut data)?;

    assert!(data.is_zeroized());

    Ok(())
}

// ============================================================================
// decrypt_field
// ============================================================================

#[test]
fn test_decrypt_field_poisons_on_a_failed_open() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;
    let mut field = RedoubtCodecTestBreaker::default();

    let result = boxed.decrypt_field::<_, 1>(&master_key()?, &mut field);

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

#[test]
fn test_decrypt_field_leaves_the_sealed_field_intact() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let before = boxed.__unsafe_get_field_ciphertext::<1>().clone();
    let mut field = RedoubtCodecTestBreaker::default();

    boxed.decrypt_field::<_, 1>(&master_key()?, &mut field)?;

    assert_eq!(boxed.__unsafe_get_field_ciphertext::<1>(), &before);

    Ok(())
}

// ============================================================================
// decrypt_field_into
// ============================================================================

/// Every way the open below can fail arrives here as one, so what a caller is
/// told is `Poisoned` and never the error underneath.
#[test]
fn test_decrypt_field_into_poisons_on_a_failed_decrypt() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;
    let mut field = RedoubtCodecTestBreaker::default();
    let mut data = Data::default();

    let result = boxed.decrypt_field_into::<_, 1>(&master_key()?, &mut field, &mut data);

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

#[test]
fn test_decrypt_field_into_poisons_on_a_failed_decode() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let mut field =
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceDecodeError, 0);
    let mut data = Data::default();

    let result = boxed.decrypt_field_into::<_, 1>(&master_key()?, &mut field, &mut data);

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

/// A decrypt that fails leaves the buffer holding a keystream over bytes
/// nobody authenticated, and a decode that fails leaves the tail it never
/// read. Neither is left for the caller to find.
#[test]
fn test_decrypt_field_into_leaves_the_lent_buffer_zeroized_on_a_failed_decrypt()
-> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;
    let mut field = RedoubtCodecTestBreaker::default();
    let mut data = Data::default();

    let result = boxed.decrypt_field_into::<_, 1>(&master_key()?, &mut field, &mut data);

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(data.is_zeroized());

    Ok(())
}

#[test]
fn test_decrypt_field_into_leaves_the_lent_buffer_zeroized_on_a_failed_decode()
-> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let mut field =
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceDecodeError, 0);
    let mut data = Data::default();

    let result = boxed.decrypt_field_into::<_, 1>(&master_key()?, &mut field, &mut data);

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(data.is_zeroized());

    Ok(())
}

#[test]
fn test_decrypt_field_into_leaves_the_lent_buffer_zeroized_on_a_read_that_succeeds()
-> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let mut field = RedoubtCodecTestBreaker::default();
    let mut data = Data::default();

    boxed.decrypt_field_into::<_, 1>(&master_key()?, &mut field, &mut data)?;

    assert!(data.is_zeroized());

    Ok(())
}

// ============================================================================
// try_encrypt_field
// ============================================================================

#[test]
fn test_try_encrypt_field_propagates_bytes_required_error() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());
    let mut field = RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
        0,
    );

    let result = boxed.try_encrypt_field::<_, 1>(&master_key()?, &mut field);

    assert!(matches!(result, Err(CipherBoxError::Overflow(_))));

    Ok(())
}

#[test]
fn test_try_encrypt_field_propagates_encode_error() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());
    let mut field =
        RedoubtCodecTestBreaker::new(RedoubtCodecTestBreakerBehaviour::ForceEncodeError, 0);

    let result = boxed.try_encrypt_field::<_, 1>(&master_key()?, &mut field);

    assert!(matches!(result, Err(CipherBoxError::Encode(_))));
    assert!(boxed.__unsafe_get_tmp_codec_buff().is_zeroized());

    Ok(())
}

/// No nonce came back, so nothing was sealed — and what the buffer holds at
/// that point is the encoded field, in plain sight.
#[test]
fn test_try_encrypt_field_propagates_generate_nonce_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthGenerateNonce(1));
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(aead);
    let mut field = RedoubtCodecTestBreaker::default();

    let result = boxed.try_encrypt_field::<_, 1>(&master_key()?, &mut field);

    assert!(matches!(
        result,
        Err(CipherBoxError::Aead(AeadError::NonceEntropy(_)))
    ));
    assert!(boxed.__unsafe_get_field_ciphertext::<1>().is_zeroized());

    Ok(())
}

#[test]
fn test_try_encrypt_field_propagates_encrypt_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(1));
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(aead);
    let mut field = RedoubtCodecTestBreaker::default();

    let result = boxed.try_encrypt_field::<_, 1>(&master_key()?, &mut field);

    assert!(matches!(result, Err(CipherBoxError::Aead(_))));
    assert!(boxed.__unsafe_get_field_ciphertext::<1>().is_zeroized());

    Ok(())
}

#[test]
fn test_try_encrypt_field_seals_the_field_it_was_given() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());
    let mut field = RedoubtCodecTestBreaker::default();

    boxed.try_encrypt_field::<_, 1>(&master_key()?, &mut field)?;

    assert!(!boxed.__unsafe_get_field_ciphertext::<1>().is_empty());

    Ok(())
}

// ============================================================================
// encrypt_field
// ============================================================================

/// A width nobody can encode is the caller asking for the impossible, not the
/// box breaking, so it answers and stays usable.
#[test]
fn test_encrypt_field_reports_overflow_without_poisoning() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());
    let mut field = RedoubtCodecTestBreaker::new(
        RedoubtCodecTestBreakerBehaviour::ForceBytesRequiredOverflow,
        0,
    );

    let result = boxed.encrypt_field::<_, 1>(&master_key()?, &mut field);

    assert!(matches!(result, Err(CipherBoxError::Overflow(_))));
    assert!(boxed.assert_healthy().is_ok());

    Ok(())
}

/// No nonce came back, so nothing was sealed and nothing here was written
/// over. A box that is intact is not poisoned.
#[test]
fn test_encrypt_field_propagates_nonce_entropy_error_without_poisoning() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthGenerateNonce(1));
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(aead);
    let mut field = RedoubtCodecTestBreaker::default();

    let result = boxed.encrypt_field::<_, 1>(&master_key()?, &mut field);

    assert!(matches!(
        result,
        Err(CipherBoxError::Aead(AeadError::NonceEntropy(_)))
    ));
    assert!(boxed.assert_healthy().is_ok());

    Ok(())
}

#[test]
fn test_encrypt_field_poisons_on_a_failed_seal() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(1));
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(aead);
    let mut field = RedoubtCodecTestBreaker::default();

    let result = boxed.encrypt_field::<_, 1>(&master_key()?, &mut field);

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

#[test]
fn test_encrypt_field_seals_the_field_it_was_given() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());
    let mut field = RedoubtCodecTestBreaker::default();

    boxed.encrypt_field::<_, 1>(&master_key()?, &mut field)?;

    assert!(!boxed.__unsafe_get_field_ciphertext::<1>().is_empty());

    Ok(())
}

// ============================================================================
// open_dyn
// ============================================================================

#[test]
fn test_open_dyn_propagates_assert_healthy_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.fast_zeroize();

    let result = boxed.open_dyn::<usize, CipherBoxError>(&mut |it| Ok(it.f0.usize.data));

    assert!(matches!(result, Err(CipherBoxError::Zeroized)));

    Ok(())
}

#[test]
fn test_open_dyn_propagates_open_value_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;

    let result = boxed.open_dyn::<usize, CipherBoxError>(&mut |it| Ok(it.f0.usize.data));

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));

    Ok(())
}

#[test]
fn test_open_dyn_propagates_callback_error() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;

    let result = boxed
        .open_dyn::<usize, CipherBoxError>(&mut |_| Err(CipherBoxError::IntentionalCipherBoxError));

    assert!(matches!(
        result,
        Err(CipherBoxError::IntentionalCipherBoxError)
    ));

    Ok(())
}

/// A callback that refuses is not the box breaking, so the sealed fields it
/// was reading are still there to read again.
#[test]
fn test_open_dyn_leaves_the_box_healthy_after_a_callback_error() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;

    let result = boxed
        .open_dyn::<usize, CipherBoxError>(&mut |_| Err(CipherBoxError::IntentionalCipherBoxError));

    assert!(result.is_err());
    assert!(boxed.assert_healthy().is_ok());

    Ok(())
}

#[test]
fn test_open_dyn_returns_what_the_callback_returned() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let expected = TestBox::default().f0.usize.data;

    let result = boxed.open_dyn::<usize, CipherBoxError>(&mut |it| Ok(it.f0.usize.data))?;

    assert_eq!(*result, expected);

    Ok(())
}

// ============================================================================
// open_value
// ============================================================================

/// The key size is one nothing can leak, so an open that reaches the master
/// key cannot come back `Ok` — and this one does, which is how an unsealed
/// box is shown never to ask for it.
#[test]
fn test_open_value_returns_the_default_without_reaching_the_master_key() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    boxed.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let value = boxed.open_value()?;

    assert_eq!(value.f0.usize.data, TestBox::default().f0.usize.data);

    Ok(())
}

/// The key never came back, so nothing was opened and nothing was written
/// over. A box that is intact is not poisoned.
#[test]
fn test_open_value_propagates_leak_master_key_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    assert!(matches!(boxed.open_value(), Err(CipherBoxError::Buffer(_))));
    assert!(boxed.assert_healthy().is_ok());

    Ok(())
}

#[test]
fn test_open_value_propagates_decrypt_struct_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;

    assert!(matches!(boxed.open_value(), Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

#[test]
fn test_open_value_returns_what_was_sealed() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let expected = TestBox::default().f5.usize.data;

    let value = boxed.open_value()?;

    assert_eq!(value.f5.usize.data, expected);

    Ok(())
}

// ============================================================================
// open_mut_dyn
// ============================================================================

#[test]
fn test_open_mut_dyn_propagates_assert_healthy_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.fast_zeroize();

    let result = boxed.open_mut_dyn::<usize, CipherBoxError>(&mut |it| Ok(it.f0.usize.data));

    assert!(matches!(result, Err(CipherBoxError::Zeroized)));

    Ok(())
}

/// The key never came back, so the callback never ran and nothing was
/// written over. A box that is intact is not poisoned.
#[test]
fn test_open_mut_dyn_propagates_leak_master_key_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result = boxed.open_mut_dyn::<usize, CipherBoxError>(&mut |it| Ok(it.f0.usize.data));

    assert!(matches!(result, Err(CipherBoxError::Buffer(_))));
    assert!(boxed.assert_healthy().is_ok());

    Ok(())
}

#[test]
fn test_open_mut_dyn_propagates_decrypt_struct_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let mut boxed = sealed(aead)?;

    let result = boxed.open_mut_dyn::<usize, CipherBoxError>(&mut |it| Ok(it.f0.usize.data));

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));

    Ok(())
}

#[test]
fn test_open_mut_dyn_propagates_callback_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    let result = boxed.open_mut_dyn::<usize, CipherBoxError>(&mut |_| {
        Err(CipherBoxError::IntentionalCipherBoxError)
    });

    assert!(matches!(
        result,
        Err(CipherBoxError::IntentionalCipherBoxError)
    ));

    Ok(())
}

/// A callback that refuses is not the box breaking, and what it was handed
/// was a clone, so what stayed sealed is what was sealed before it ran.
#[test]
fn test_open_mut_dyn_rolls_back_a_callback_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;
    let before = boxed.__unsafe_get_ciphertexts().clone();

    let result = boxed.open_mut_dyn::<usize, CipherBoxError>(&mut |it| {
        it.f0.usize.data = 999;

        Err(CipherBoxError::IntentionalCipherBoxError)
    });

    assert!(result.is_err());
    assert!(boxed.assert_healthy().is_ok());
    assert_eq!(boxed.__unsafe_get_ciphertexts(), &before);

    Ok(())
}

/// Sealing a box spends one encrypt per field, so `NUM_FIELDS + 1` is the
/// reseal's first.
#[test]
fn test_open_mut_dyn_propagates_encrypt_struct_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(NUM_FIELDS + 1));
    let mut boxed = sealed(aead)?;

    let result = boxed.open_mut_dyn::<usize, CipherBoxError>(&mut |it| {
        it.f0.usize.data = 999;

        Ok(0)
    });

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

/// The reseal on the way out is what first seals an unsealed box, so nothing
/// needs to have sealed it before the write.
#[test]
fn test_open_mut_dyn_seals_an_unsealed_box_with_what_the_callback_wrote() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    boxed.open_mut_dyn::<usize, CipherBoxError>(&mut |it| {
        it.f0.usize.data = 999;

        Ok(0)
    })?;

    let value = boxed.open_value()?;

    assert_eq!(value.f0.usize.data, 999);

    Ok(())
}

#[test]
fn test_open_mut_dyn_commits_what_the_callback_wrote() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.open_mut_dyn::<usize, CipherBoxError>(&mut |it| {
        it.f3.usize.data = 12345;

        Ok(0)
    })?;

    let value = boxed.open_value()?;

    assert_eq!(value.f3.usize.data, 12345);

    Ok(())
}

// ============================================================================
// open_field_dyn
// ============================================================================

#[test]
fn test_open_field_dyn_propagates_assert_healthy_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.fast_zeroize();

    let result =
        boxed.open_field_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |it| {
            Ok(it.usize.data)
        });

    assert!(matches!(result, Err(CipherBoxError::Zeroized)));

    Ok(())
}

#[test]
fn test_open_field_dyn_propagates_open_field_value_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;

    let result =
        boxed.open_field_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |it| {
            Ok(it.usize.data)
        });

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));

    Ok(())
}

#[test]
fn test_open_field_dyn_propagates_callback_error() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;

    let result =
        boxed.open_field_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |_| {
            Err(CipherBoxError::IntentionalCipherBoxError)
        });

    assert!(matches!(
        result,
        Err(CipherBoxError::IntentionalCipherBoxError)
    ));

    Ok(())
}

#[test]
fn test_open_field_dyn_returns_what_the_callback_returned() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let expected = TestBox::default().f1.usize.data;

    let result =
        boxed.open_field_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |it| {
            Ok(it.usize.data)
        })?;

    assert_eq!(*result, expected);

    Ok(())
}

// ============================================================================
// open_field_value
// ============================================================================

/// The key size is one nothing can leak, so an open that reaches the master
/// key cannot come back `Ok` — and this one does, which is how an unsealed
/// box is shown never to ask for it.
#[test]
fn test_open_field_value_returns_the_default_without_reaching_the_master_key()
-> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    boxed.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let field = boxed.open_field_value::<RedoubtCodecTestBreaker, 1>()?;

    assert_eq!(
        field.usize.data,
        RedoubtCodecTestBreaker::default().usize.data
    );

    Ok(())
}

/// The key never came back, so nothing was opened and nothing was written
/// over. A box that is intact is not poisoned.
#[test]
fn test_open_field_value_propagates_leak_master_key_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result = boxed.open_field_value::<RedoubtCodecTestBreaker, 1>();

    assert!(matches!(result, Err(CipherBoxError::Buffer(_))));
    assert!(boxed.assert_healthy().is_ok());

    Ok(())
}

#[test]
fn test_open_field_value_propagates_decrypt_field_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;

    let result = boxed.open_field_value::<RedoubtCodecTestBreaker, 1>();

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

#[test]
fn test_open_field_value_returns_what_was_sealed() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let expected = TestBox::default().f4.usize.data;

    let field = boxed.open_field_value::<RedoubtCodecTestBreaker, 4>()?;

    assert_eq!(field.usize.data, expected);

    Ok(())
}

// ============================================================================
// open_field_mut_dyn
// ============================================================================

#[test]
fn test_open_field_mut_dyn_propagates_assert_healthy_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.fast_zeroize();

    let result =
        boxed.open_field_mut_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |it| {
            Ok(it.usize.data)
        });

    assert!(matches!(result, Err(CipherBoxError::Zeroized)));

    Ok(())
}

#[test]
fn test_open_field_mut_dyn_propagates_maybe_initialize_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(1));
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(aead);

    let result =
        boxed.open_field_mut_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |it| {
            Ok(it.usize.data)
        });

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));

    Ok(())
}

/// The key never came back, so the callback never ran and nothing was
/// written over. A box that is intact is not poisoned.
///
/// Sealed first on purpose: `maybe_initialize` asks for the master key too,
/// and on a box it has to seal it would be the one that failed.
#[test]
fn test_open_field_mut_dyn_propagates_leak_master_key_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.__unsafe_change_api_key_size(MASTER_KEY_LEN + 1);

    let result =
        boxed.open_field_mut_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |it| {
            Ok(it.usize.data)
        });

    assert!(matches!(result, Err(CipherBoxError::Buffer(_))));
    assert!(boxed.assert_healthy().is_ok());

    Ok(())
}

#[test]
fn test_open_field_mut_dyn_propagates_decrypt_field_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let mut boxed = sealed(aead)?;

    let result =
        boxed.open_field_mut_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |it| {
            Ok(it.usize.data)
        });

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

#[test]
fn test_open_field_mut_dyn_propagates_callback_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    let result =
        boxed.open_field_mut_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |_| {
            Err(CipherBoxError::IntentionalCipherBoxError)
        });

    assert!(matches!(
        result,
        Err(CipherBoxError::IntentionalCipherBoxError)
    ));

    Ok(())
}

/// Sealing a box spends one encrypt per field, so `NUM_FIELDS + 1` is the
/// one this reseals its field with.
#[test]
fn test_open_field_mut_dyn_propagates_encrypt_field_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthEncrypt(NUM_FIELDS + 1));
    let mut boxed = sealed(aead)?;

    let result =
        boxed.open_field_mut_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |it| {
            it.usize.data = 999;

            Ok(0)
        });

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));
    assert!(boxed.assert_healthy().is_err());

    Ok(())
}

/// A write that reaches one field seals that one and leaves the rest as they
/// were, so on a box nothing had sealed the rest would stay empty and the
/// next read would answer with the default, losing this write.
#[test]
fn test_open_field_mut_dyn_seals_every_field_of_an_unsealed_box() -> Result<(), BoxError> {
    let mut boxed = CipherBox::<TestBox, NUM_FIELDS>::new(Aead::default());

    boxed.open_field_mut_dyn::<RedoubtCodecTestBreaker, 1, usize, CipherBoxError>(&mut |it| {
        it.usize.data = 777;

        Ok(0)
    })?;

    assert!(
        boxed
            .__unsafe_get_ciphertexts()
            .iter()
            .all(|it| !it.is_empty())
    );

    let value = boxed.open_value()?;

    assert_eq!(value.f1.usize.data, 777);

    Ok(())
}

#[test]
fn test_open_field_mut_dyn_commits_what_the_callback_wrote() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.open_field_mut_dyn::<RedoubtCodecTestBreaker, 2, usize, CipherBoxError>(&mut |it| {
        it.usize.data = 4242;

        Ok(0)
    })?;

    let field = boxed.open_field_value::<RedoubtCodecTestBreaker, 2>()?;

    assert_eq!(field.usize.data, 4242);

    Ok(())
}

// ============================================================================
// open
// ============================================================================

/// The closure arrives as a generic and leaves as a `&mut dyn FnMut`, so what
/// this pins is that the one the caller wrote is the one that ran.
#[test]
fn test_open_hands_the_struct_to_the_closure() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let expected = TestBox::default().f2.usize.data;

    let result = boxed.open::<_, usize, CipherBoxError>(|it| Ok(it.f2.usize.data))?;

    assert_eq!(*result, expected);

    Ok(())
}

#[test]
fn test_open_propagates_open_dyn_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.fast_zeroize();

    let result = boxed.open::<_, usize, CipherBoxError>(|it| Ok(it.f2.usize.data));

    assert!(matches!(result, Err(CipherBoxError::Zeroized)));

    Ok(())
}

// ============================================================================
// open_mut
// ============================================================================

#[test]
fn test_open_mut_hands_the_struct_to_the_closure() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.open_mut::<_, usize, CipherBoxError>(|it| {
        it.f2.usize.data = 31337;

        Ok(0)
    })?;

    let value = boxed.open_value()?;

    assert_eq!(value.f2.usize.data, 31337);

    Ok(())
}

#[test]
fn test_open_mut_propagates_open_mut_dyn_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.fast_zeroize();

    let result = boxed.open_mut::<_, usize, CipherBoxError>(|it| Ok(it.f2.usize.data));

    assert!(matches!(result, Err(CipherBoxError::Zeroized)));

    Ok(())
}

// ============================================================================
// open_field
// ============================================================================

#[test]
fn test_open_field_hands_the_field_to_the_closure() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let expected = TestBox::default().f3.usize.data;

    let result =
        boxed.open_field::<RedoubtCodecTestBreaker, 3, _, usize, CipherBoxError>(|it| {
            Ok(it.usize.data)
        })?;

    assert_eq!(*result, expected);

    Ok(())
}

#[test]
fn test_open_field_propagates_open_field_dyn_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.fast_zeroize();

    let result = boxed
        .open_field::<RedoubtCodecTestBreaker, 3, _, usize, CipherBoxError>(|it| Ok(it.usize.data));

    assert!(matches!(result, Err(CipherBoxError::Zeroized)));

    Ok(())
}

// ============================================================================
// open_field_mut
// ============================================================================

#[test]
fn test_open_field_mut_hands_the_field_to_the_closure() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.open_field_mut::<RedoubtCodecTestBreaker, 3, _, usize, CipherBoxError>(|it| {
        it.usize.data = 5150;

        Ok(0)
    })?;

    let field = boxed.open_field_value::<RedoubtCodecTestBreaker, 3>()?;

    assert_eq!(field.usize.data, 5150);

    Ok(())
}

#[test]
fn test_open_field_mut_propagates_open_field_mut_dyn_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.fast_zeroize();

    let result =
        boxed.open_field_mut::<RedoubtCodecTestBreaker, 3, _, usize, CipherBoxError>(|it| {
            Ok(it.usize.data)
        });

    assert!(matches!(result, Err(CipherBoxError::Zeroized)));

    Ok(())
}

// ============================================================================
// leak_field
// ============================================================================

#[test]
fn test_leak_field_propagates_assert_healthy_error() -> Result<(), BoxError> {
    let mut boxed = sealed(Aead::default())?;

    boxed.fast_zeroize();

    let result = boxed.leak_field::<RedoubtCodecTestBreaker, 4, CipherBoxError>();

    assert!(matches!(result, Err(CipherBoxError::Zeroized)));

    Ok(())
}

#[test]
fn test_leak_field_propagates_open_field_value_error() -> Result<(), BoxError> {
    let aead = Aead::default().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let boxed = sealed(aead)?;

    let result = boxed.leak_field::<RedoubtCodecTestBreaker, 4, CipherBoxError>();

    assert!(matches!(result, Err(CipherBoxError::Poisoned)));

    Ok(())
}

/// The field is handed out rather than shown through a callback, and the box
/// keeps it sealed, so the caller holds a copy nobody has to give back.
#[test]
fn test_leak_field_returns_the_field_and_keeps_it_sealed() -> Result<(), BoxError> {
    let boxed = sealed(Aead::default())?;
    let expected = TestBox::default().f4.usize.data;
    let before = boxed.__unsafe_get_field_ciphertext::<4>().clone();

    let field = boxed.leak_field::<RedoubtCodecTestBreaker, 4, CipherBoxError>()?;

    assert_eq!(field.usize.data, expected);
    assert_eq!(boxed.__unsafe_get_field_ciphertext::<4>(), &before);

    Ok(())
}
