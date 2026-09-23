// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod algorithms;

use alloc::boxed::Box;
use alloc::vec::Vec;

use proptest::prelude::*;

use redoubt_aead_core::consts::{aegis, chacha, poly1305};
use redoubt_aead_core::{AeadCoreError, AeadDecrypt, AeadEncrypt};
use redoubt_aead_xchachapoly1305::XChaCha20Poly1305;
use redoubt_rand::{
    EntropyError, NonceSessionGenerator, NonceSessionGeneratorBehaviour, SystemEntropySource,
};

#[cfg(aes_asm)]
use redoubt_aead_aegis128l::Aegis128L;

use crate::aead::{Aead, Session};
use crate::enums::{AeadAlgorithm, AeadBehaviour};
use crate::errors::AeadError;
use crate::feature_detector::{FeatureDetector, FeatureDetectorBehaviour};

/// Past the widest either cipher takes, so a sweep reaches both sides of every
/// boundary rather than sampling around them.
const WIDEST: usize = 48;

fn filled(width: usize) -> Vec<u8> {
    (0..width).map(|at| (at as u8) ^ 0x5a).collect()
}

/// Every width up to `WIDEST` except the one that fits.
fn every_width_but(right: usize) -> impl Iterator<Item = usize> {
    (0..=WIDEST).filter(move |given| *given != right)
}

/// The three fields, so that a width reported against the wrong cipher, or with
/// the wrong number in either place, is a failure rather than a pass.
macro_rules! assert_width {
    ($result:expr, $variant:ident, $algorithm:expr, $expected:expr, $given:expr, $said:literal) => {
        assert!(
            matches!(
                $result,
                Err(AeadError::$variant {
                    algorithm,
                    expected,
                    given,
                }) if algorithm == $algorithm && expected == $expected && given == $given
            ),
            concat!($said, " of {} bytes against {} expected"),
            $given,
            $expected
        )
    };
}

/// A detector that answers the given thing whatever the machine is.
fn forced(behaviour: FeatureDetectorBehaviour) -> FeatureDetector {
    FeatureDetector::default().with_behaviour(behaviour)
}

/// Every algorithm this target can run, which is every one a caller is handed.
fn every_algorithm() -> Vec<AeadAlgorithm> {
    #[cfg_attr(not(aes_asm), allow(unused_mut))]
    let mut algorithms = Vec::from([AeadAlgorithm::XChachaPoly1305]);

    #[cfg(aes_asm)]
    algorithms.push(AeadAlgorithm::Aegis128L);

    algorithms
}

/// Every answer a detector can be told to give on this target.
///
/// A target with no AEGIS assembly has no `ForceAesTrue` to be told, because
/// forcing it would name a machine that cannot exist.
fn every_behaviour() -> Vec<FeatureDetectorBehaviour> {
    #[cfg_attr(not(aes_asm), allow(unused_mut))]
    let mut behaviours = Vec::from([FeatureDetectorBehaviour::ForceAesFalse]);

    #[cfg(aes_asm)]
    behaviours.push(FeatureDetectorBehaviour::ForceAesTrue);

    behaviours
}

/// A generator that answers a failure the machine itself never answers, so a
/// case below cannot pass on a real shortage of entropy.
fn refusing<const N: usize>() -> NonceSessionGenerator<SystemEntropySource, N> {
    NonceSessionGenerator::new(SystemEntropySource {})
        .with_behaviour(NonceSessionGeneratorBehaviour::FailAtGenerateNonce)
}

/// The counter a nonce opens with, which is the part two from one session
/// cannot repeat.
fn counter_of(nonce: &[u8]) -> u32 {
    u32::from_le_bytes(
        nonce[..size_of::<u32>()]
            .try_into()
            .expect("a nonce is wider than its counter"),
    )
}

/// Without it, every case that asks for AEGIS gets the fallback and passes.
#[test]
#[cfg(aes_asm)]
fn test_this_machine_has_aes() {
    assert!(
        FeatureDetector::default().supports_aes(),
        "this machine has no aes"
    );
}

// === === === === === === === === === ===
// FeatureDetectorBehaviour
// === === === === === === === === === ===

/// A `#[default]` that moved would leave every detector forcing an answer
/// instead of asking the machine, and the cases that force one would agree
/// with it.
#[test]
fn test_behaviour_default_returns_none() {
    assert!(matches!(
        FeatureDetectorBehaviour::default(),
        FeatureDetectorBehaviour::None
    ));
}

// === === === === === === === === === ===
// Shared use
// === === === === === === === === === ===

fn assert_sync<T: Sync>() {}
fn assert_send<T: Send>() {}

/// Opening takes the cipher by shared reference, so one of these can be held
/// by several threads that read through it at once.
///
/// Nothing declares that: it holds because every field is plain data or an
/// atomic, the nonce counter included. A `Cell` in any of them — the session,
/// the fuse — takes it away, and the consumer that can no longer share it is
/// where that would otherwise be found.
#[test]
fn test_a_cipher_can_be_held_by_several_threads() {
    assert_sync::<Aead>();
    assert_send::<Aead>();
}

// === === === === === === === === === ===
// algorithm
// === === === === === === === === === ===

#[test]
fn test_algorithm_answers_what_the_constructor_chose() {
    assert_eq!(
        Aead::new_chacha().algorithm(),
        AeadAlgorithm::XChachaPoly1305
    );
}

// === === === === === === === === === ===
// key_size
// === === === === === === === === === ===

/// What an `Aead` reports is what the cipher it runs takes, and a caller that
/// prepares a key of it is handed no `KeyWidth`.
#[test]
fn test_key_size_is_the_width_encrypt_accepts() {
    for algorithm in every_algorithm() {
        let aead = Aead::from_algorithm(algorithm);
        let mut data = filled(64);
        let mut tag = filled(aead.tag_size());

        let result = aead.encrypt(
            &filled(aead.key_size()),
            &filled(aead.nonce_size()),
            b"",
            &mut data,
            &mut tag,
        );

        assert!(
            matches!(result, Ok(())),
            "{algorithm:?} refused the widths it reports: {result:?}"
        );
    }
}

// === === === === === === === === === ===
// nonce_size
// === === === === === === === === === ===

/// The nonce a caller is told to prepare is the one `generate_nonce` hands
/// back, so asking and being given cannot disagree.
#[test]
fn test_nonce_size_is_the_width_generate_nonce_answers()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for algorithm in every_algorithm() {
        let mut aead = Aead::from_algorithm(algorithm);

        let nonce = aead.generate_nonce()?;

        assert_eq!(nonce.len(), aead.nonce_size(), "{algorithm:?}");
    }

    Ok(())
}

// === === === === === === === === === ===
// tag_size
// === === === === === === === === === ===

/// A buffer of this width is one the sealing fills rather than refuses, which
/// is what a caller sizing a tag from it is relying on.
#[test]
fn test_tag_size_is_the_width_encrypt_writes()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for algorithm in every_algorithm() {
        let aead = Aead::from_algorithm(algorithm);
        let mut data = filled(64);
        let mut tag = filled(aead.tag_size());
        let before = tag.clone();

        aead.encrypt(
            &filled(aead.key_size()),
            &filled(aead.nonce_size()),
            b"",
            &mut data,
            &mut tag,
        )?;

        assert_ne!(tag, before, "{algorithm:?} wrote no tag");
    }

    Ok(())
}

// === === === === === === === === === ===
// generate_nonce_with
// === === === === === === === === === ===

#[test]
fn test_generate_nonce_with_propagates_chacha_entropy_error() {
    let mut session = Session::XChachaPoly1305(refusing());

    let result = Aead::generate_nonce_with(&mut session);

    assert!(
        matches!(result, Err(AeadError::NonceEntropy(EntropyError::Injected))),
        "a refused nonce came back as {result:?}"
    );
}

#[test]
fn test_generate_nonce_with_propagates_aegis_entropy_error() {
    let mut session = Session::Aegis128L(refusing());

    let result = Aead::generate_nonce_with(&mut session);

    assert!(
        matches!(result, Err(AeadError::NonceEntropy(EntropyError::Injected))),
        "a refused nonce came back as {result:?}"
    );
}

#[test]
fn test_generate_nonce_with_answers_a_nonce_of_the_chacha_width()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::XChachaPoly1305(NonceSessionGenerator::new(SystemEntropySource {}));

    let nonce = Aead::generate_nonce_with(&mut session)?;

    assert_eq!(nonce.len(), chacha::XNONCE_SIZE);

    Ok(())
}

#[test]
fn test_generate_nonce_with_answers_a_nonce_of_the_aegis_width()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::Aegis128L(NonceSessionGenerator::new(SystemEntropySource {}));

    let nonce = Aead::generate_nonce_with(&mut session)?;

    assert_eq!(nonce.len(), aegis::NONCE_SIZE);

    Ok(())
}

// === === === === === === === === === ===
// generate_nonce
// === === === === === === === === === ===

#[test]
fn test_generate_nonce_propagates_the_fuse_at_the_first_call() {
    let mut aead = Aead::new_chacha().with_behaviour(AeadBehaviour::FailAtNthGenerateNonce(1));

    let result = aead.generate_nonce();

    assert!(
        matches!(result, Err(AeadError::NonceEntropy(EntropyError::Injected))),
        "a refused nonce came back as {result:?}"
    );
}

#[test]
fn test_generate_nonce_propagates_the_fuse_at_the_nth_call()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut aead = Aead::new_chacha().with_behaviour(AeadBehaviour::FailAtNthGenerateNonce(2));

    let first = aead.generate_nonce()?;

    assert_eq!(first.len(), chacha::XNONCE_SIZE);

    let result = aead.generate_nonce();

    assert!(
        matches!(result, Err(AeadError::NonceEntropy(EntropyError::Injected))),
        "a refused nonce came back as {result:?}"
    );

    Ok(())
}

#[test]
fn test_generate_nonce_answers_a_nonce_of_the_chacha_width()
-> Result<(), Box<dyn std::error::Error>> {
    let mut aead = Aead::new_chacha();

    let nonce = aead.generate_nonce()?;

    assert_eq!(nonce.len(), chacha::XNONCE_SIZE);

    Ok(())
}

#[test]
#[cfg(aes_asm)]
fn test_generate_nonce_answers_a_nonce_of_the_aegis_width() -> Result<(), Box<dyn std::error::Error>>
{
    let mut aead = Aead::from_algorithm(AeadAlgorithm::Aegis128L);

    let nonce = aead.generate_nonce()?;

    assert_eq!(nonce.len(), aegis::NONCE_SIZE);

    Ok(())
}

/// The counter is what makes two nonces unable to collide, and it only counts
/// for an `Aead` that is kept: one built per message answers from a generator
/// that has issued nothing.
#[test]
fn test_generate_nonce_answers_the_next_counter_each_time() -> Result<(), Box<dyn std::error::Error>>
{
    let mut aead = Aead::new_chacha();

    let first = counter_of(&aead.generate_nonce()?);
    let second = counter_of(&aead.generate_nonce()?);

    assert_eq!(second, first.wrapping_add(1));

    Ok(())
}

// === === === === === === === === === ===
// new_with
// === === === === === === === === === ===

#[test]
fn test_new_with_takes_chacha_where_there_is_no_aes() {
    let aead = Aead::new_with(&forced(FeatureDetectorBehaviour::ForceAesFalse));

    assert_eq!(aead.algorithm(), AeadAlgorithm::XChachaPoly1305);
}

#[test]
#[cfg(aes_asm)]
fn test_new_with_takes_aegis_where_there_is_aes() {
    let aead = Aead::new_with(&forced(FeatureDetectorBehaviour::ForceAesTrue));

    assert_eq!(aead.algorithm(), AeadAlgorithm::Aegis128L);
}

#[test]
#[cfg(aes_asm)]
fn test_new_with_takes_aegis_on_this_machine() {
    let aead = Aead::new_with(&FeatureDetector::default());

    assert_eq!(aead.algorithm(), AeadAlgorithm::Aegis128L);
}

// === === === === === === === === === ===
// default
// === === === === === === === === === ===

/// Resolving the detector is the one step a forced one cannot reach.
#[test]
#[cfg(aes_asm)]
fn test_default_takes_what_this_machine_allows() {
    assert_eq!(Aead::default().algorithm(), AeadAlgorithm::Aegis128L);
}

// === === === === === === === === === ===
// new_chacha
// === === === === === === === === === ===

#[test]
fn test_new_chacha_takes_chacha_whatever_the_machine_is() {
    assert_eq!(
        Aead::new_chacha().algorithm(),
        AeadAlgorithm::XChachaPoly1305
    );
}

// === === === === === === === === === ===
// new_aegis
// === === === === === === === === === ===

#[test]
fn test_new_aegis_answers_with_nothing_where_there_is_no_aes() {
    let aead = Aead::new_aegis(&forced(FeatureDetectorBehaviour::ForceAesFalse));

    assert!(aead.is_none());
}

#[test]
#[cfg(aes_asm)]
fn test_new_aegis_takes_aegis_where_there_is_aes() {
    let aead = Aead::new_aegis(&forced(FeatureDetectorBehaviour::ForceAesTrue))
        .expect("Infallible: the detector was forced to say it has aes");

    assert_eq!(aead.algorithm(), AeadAlgorithm::Aegis128L);
}

#[test]
#[cfg(aes_asm)]
fn test_new_aegis_takes_aegis_on_this_machine() {
    let aead =
        Aead::new_aegis(&FeatureDetector::default()).expect("Infallible: this machine has aes");

    assert_eq!(aead.algorithm(), AeadAlgorithm::Aegis128L);
}

// === === === === === === === === === ===
// supported_algorithms_with
// === === === === === === === === === ===

#[test]
fn test_supported_algorithms_with_names_chacha_where_there_is_no_aes() {
    let supported =
        Aead::supported_algorithms_with(&forced(FeatureDetectorBehaviour::ForceAesFalse));

    assert_eq!(supported.as_slice(), [AeadAlgorithm::XChachaPoly1305]);
}

#[test]
#[cfg(aes_asm)]
fn test_supported_algorithms_with_names_both_where_there_is_aes() {
    let supported =
        Aead::supported_algorithms_with(&forced(FeatureDetectorBehaviour::ForceAesTrue));

    assert_eq!(
        supported.as_slice(),
        [AeadAlgorithm::XChachaPoly1305, AeadAlgorithm::Aegis128L]
    );
}

/// The list is never empty, whatever the machine answers.
///
/// XChaCha20-Poly1305 needs nothing of the hardware, so it is in the list by
/// construction rather than because some machine happened to allow it.
#[test]
fn test_supported_algorithms_with_always_names_chacha() {
    for behaviour in every_behaviour() {
        let supported = Aead::supported_algorithms_with(&forced(behaviour));

        assert!(supported.contains(&AeadAlgorithm::XChachaPoly1305));
    }
}

// === === === === === === === === === ===
// supported_algorithms
// === === === === === === === === === ===

#[test]
#[cfg(aes_asm)]
fn test_supported_algorithms_names_what_this_machine_allows() {
    assert_eq!(
        Aead::supported_algorithms().as_slice(),
        [AeadAlgorithm::XChachaPoly1305, AeadAlgorithm::Aegis128L]
    );
}

// === === === === === === === === === ===
// variants_with
// === === === === === === === === === ===

#[test]
fn test_variants_with_answers_with_chacha_where_there_is_no_aes() {
    let variants = Aead::variants_with(&forced(FeatureDetectorBehaviour::ForceAesFalse));

    assert_eq!(
        variants.xchachapoly1305.algorithm(),
        AeadAlgorithm::XChachaPoly1305
    );
    assert!(variants.aegis128l.is_none());
}

#[test]
#[cfg(aes_asm)]
fn test_variants_with_answers_with_both_where_there_is_aes() {
    let variants = Aead::variants_with(&forced(FeatureDetectorBehaviour::ForceAesTrue));

    assert_eq!(
        variants.xchachapoly1305.algorithm(),
        AeadAlgorithm::XChachaPoly1305
    );
    assert_eq!(
        variants
            .aegis128l
            .expect("Infallible: the detector was forced to say it has aes")
            .algorithm(),
        AeadAlgorithm::Aegis128L
    );
}

#[test]
fn test_variants_with_always_answers_with_chacha() {
    for behaviour in every_behaviour() {
        let variants = Aead::variants_with(&forced(behaviour));

        assert_eq!(
            variants.xchachapoly1305.algorithm(),
            AeadAlgorithm::XChachaPoly1305
        );
    }
}

// === === === === === === === === === ===
// variants
// === === === === === === === === === ===

#[test]
#[cfg(aes_asm)]
fn test_variants_answers_with_what_this_machine_allows() {
    let variants = Aead::variants();

    assert_eq!(
        variants.xchachapoly1305.algorithm(),
        AeadAlgorithm::XChachaPoly1305
    );
    assert_eq!(
        variants
            .aegis128l
            .expect("Infallible: this machine has aes")
            .algorithm(),
        AeadAlgorithm::Aegis128L
    );
}

// === === === === === === === === === ===
// from_algorithm
// === === === === === === === === === ===

#[test]
fn test_from_algorithm_answers_with_the_one_it_was_named() {
    assert_eq!(
        Aead::from_algorithm(AeadAlgorithm::XChachaPoly1305).algorithm(),
        AeadAlgorithm::XChachaPoly1305
    );
}

#[test]
#[cfg(aes_asm)]
fn test_from_algorithm_answers_with_aegis_when_it_is_named() {
    assert_eq!(
        Aead::from_algorithm(AeadAlgorithm::Aegis128L).algorithm(),
        AeadAlgorithm::Aegis128L
    );
}

#[test]
#[cfg(aes_asm)]
fn test_from_algorithm_reaches_every_algorithm_this_machine_names() {
    for &algorithm in Aead::supported_algorithms().iter() {
        assert_eq!(Aead::from_algorithm(algorithm).algorithm(), algorithm);
    }
}

// === === === === === === === === === ===
// encrypt
// === === === === === === === === === ===

#[test]
fn test_encrypt_propagates_the_fuse_at_the_first_call() {
    let aead = Aead::new_chacha().with_behaviour(AeadBehaviour::FailAtNthEncrypt(1));
    let mut data = filled(64);
    let mut tag = filled(poly1305::TAG_SIZE);
    let sealed = data.clone();

    let result = aead.encrypt(
        &filled(chacha::KEY_SIZE),
        &filled(chacha::XNONCE_SIZE),
        b"",
        &mut data,
        &mut tag,
    );

    assert!(
        matches!(result, Err(AeadError::Core(AeadCoreError::Injected))),
        "a refused encrypt came back as {result:?}"
    );
    assert_eq!(data, sealed, "a refused encrypt still touched the message");
}

#[test]
fn test_encrypt_propagates_the_fuse_at_the_nth_call()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let aead = Aead::new_chacha().with_behaviour(AeadBehaviour::FailAtNthEncrypt(2));
    let mut data = filled(64);
    let mut tag = filled(poly1305::TAG_SIZE);
    let plain = data.clone();

    aead.encrypt(
        &filled(chacha::KEY_SIZE),
        &filled(chacha::XNONCE_SIZE),
        b"",
        &mut data,
        &mut tag,
    )?;

    assert_ne!(data, plain, "the first call sealed nothing");

    let result = aead.encrypt(
        &filled(chacha::KEY_SIZE),
        &filled(chacha::XNONCE_SIZE),
        b"",
        &mut data,
        &mut tag,
    );

    assert!(
        matches!(result, Err(AeadError::Core(AeadCoreError::Injected))),
        "a refused encrypt came back as {result:?}"
    );

    Ok(())
}

#[test]
fn test_encrypt_refuses_invalid_inputs_for_xchacha_variant() {
    let aead = Aead::from_algorithm(AeadAlgorithm::XChachaPoly1305);

    for given in every_width_but(chacha::KEY_SIZE) {
        let mut data = filled(64);
        let mut tag = filled(poly1305::TAG_SIZE);

        let result = aead.encrypt(
            &filled(given),
            &filled(chacha::XNONCE_SIZE),
            b"",
            &mut data,
            &mut tag,
        );

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::XChachaPoly1305,
            chacha::KEY_SIZE,
            given,
            "a key"
        );
    }

    for given in every_width_but(chacha::XNONCE_SIZE) {
        let mut data = filled(64);
        let mut tag = filled(poly1305::TAG_SIZE);

        let result = aead.encrypt(
            &filled(chacha::KEY_SIZE),
            &filled(given),
            b"",
            &mut data,
            &mut tag,
        );

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::XChachaPoly1305,
            chacha::XNONCE_SIZE,
            given,
            "a nonce"
        );
    }

    for given in every_width_but(poly1305::TAG_SIZE) {
        let mut data = filled(64);
        let mut tag = filled(given);

        let result = aead.encrypt(
            &filled(chacha::KEY_SIZE),
            &filled(chacha::XNONCE_SIZE),
            b"",
            &mut data,
            &mut tag,
        );

        assert_width!(
            result,
            TagWidth,
            AeadAlgorithm::XChachaPoly1305,
            poly1305::TAG_SIZE,
            given,
            "a tag"
        );
    }
}

#[test]
#[cfg(aes_asm)]
fn test_encrypt_refuses_invalid_inputs_for_aegis_variant() {
    let aead = Aead::from_algorithm(AeadAlgorithm::Aegis128L);

    for given in every_width_but(aegis::KEY_SIZE) {
        let mut data = filled(64);
        let mut tag = filled(aegis::TAG_SIZE);

        let result = aead.encrypt(
            &filled(given),
            &filled(aegis::NONCE_SIZE),
            b"",
            &mut data,
            &mut tag,
        );

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::Aegis128L,
            aegis::KEY_SIZE,
            given,
            "a key"
        );
    }

    for given in every_width_but(aegis::NONCE_SIZE) {
        let mut data = filled(64);
        let mut tag = filled(aegis::TAG_SIZE);

        let result = aead.encrypt(
            &filled(aegis::KEY_SIZE),
            &filled(given),
            b"",
            &mut data,
            &mut tag,
        );

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::Aegis128L,
            aegis::NONCE_SIZE,
            given,
            "a nonce"
        );
    }

    for given in every_width_but(aegis::TAG_SIZE) {
        let mut data = filled(64);
        let mut tag = filled(given);

        let result = aead.encrypt(
            &filled(aegis::KEY_SIZE),
            &filled(aegis::NONCE_SIZE),
            b"",
            &mut data,
            &mut tag,
        );

        assert_width!(
            result,
            TagWidth,
            AeadAlgorithm::Aegis128L,
            aegis::TAG_SIZE,
            given,
            "a tag"
        );
    }
}

proptest! {
    /// What the facade answers is what the cipher answers, byte for byte.
    ///
    /// It reads as though it asked the code about itself, and what it pins is
    /// the wiring rather than the cipher: the arm the match takes, and the
    /// order the five arguments arrive in. Two of them swapped is a cipher that
    /// still runs and a ciphertext nobody else can open.
    ///
    /// The widths differ today, so a swap would not compile. That is a property
    /// of these two ciphers and not of this function.
    #[test]
    fn test_encrypt_answers_what_xchacha_answers(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform24(any::<u8>()),
        aad in prop::collection::vec(any::<u8>(), 0..96),
        message in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut through = message.clone();
        let mut through_tag = [0_u8; poly1305::TAG_SIZE];

        Aead::from_algorithm(AeadAlgorithm::XChachaPoly1305)
            .encrypt(&key, &nonce, &aad, &mut through, &mut through_tag)?;

        let mut direct = message.clone();
        let mut direct_tag = [0_u8; poly1305::TAG_SIZE];

        XChaCha20Poly1305::new().encrypt(&key, &nonce, &aad, &mut direct, &mut direct_tag);

        prop_assert_eq!(through, direct);
        prop_assert_eq!(through_tag, direct_tag);
    }
}

#[cfg(aes_asm)]
proptest! {
    #[test]
    fn test_encrypt_answers_what_aegis_answers(
        key in prop::array::uniform16(any::<u8>()),
        nonce in prop::array::uniform16(any::<u8>()),
        aad in prop::collection::vec(any::<u8>(), 0..96),
        message in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut through = message.clone();
        let mut through_tag = [0_u8; aegis::TAG_SIZE];

        Aead::from_algorithm(AeadAlgorithm::Aegis128L)
            .encrypt(&key, &nonce, &aad, &mut through, &mut through_tag)?;

        let mut direct = message.clone();
        let mut direct_tag = [0_u8; aegis::TAG_SIZE];

        Aegis128L::new().encrypt(&key, &nonce, &aad, &mut direct, &mut direct_tag);

        prop_assert_eq!(through, direct);
        prop_assert_eq!(through_tag, direct_tag);
    }
}

// === === === === === === === === === ===
// decrypt
// === === === === === === === === === ===

#[test]
fn test_decrypt_propagates_the_fuse_at_the_first_call() {
    let aead = Aead::new_chacha().with_behaviour(AeadBehaviour::FailAtNthDecrypt(1));
    let mut data = filled(64);
    let sealed = data.clone();

    let result = aead.decrypt(
        &filled(chacha::KEY_SIZE),
        &filled(chacha::XNONCE_SIZE),
        b"",
        &mut data,
        &filled(poly1305::TAG_SIZE),
    );

    assert!(
        matches!(result, Err(AeadError::Core(AeadCoreError::Injected))),
        "a refused decrypt came back as {result:?}"
    );
    assert_eq!(
        data, sealed,
        "a refused decrypt still touched the ciphertext"
    );
}

#[test]
fn test_decrypt_propagates_the_fuse_at_the_nth_call()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let aead = Aead::new_chacha().with_behaviour(AeadBehaviour::FailAtNthDecrypt(2));
    let mut data = filled(64);
    let mut tag = filled(poly1305::TAG_SIZE);
    let plain = data.clone();

    aead.encrypt(
        &filled(chacha::KEY_SIZE),
        &filled(chacha::XNONCE_SIZE),
        b"",
        &mut data,
        &mut tag,
    )?;

    aead.decrypt(
        &filled(chacha::KEY_SIZE),
        &filled(chacha::XNONCE_SIZE),
        b"",
        &mut data,
        &tag,
    )?;

    assert_eq!(data, plain, "the first call opened nothing");

    let result = aead.decrypt(
        &filled(chacha::KEY_SIZE),
        &filled(chacha::XNONCE_SIZE),
        b"",
        &mut data,
        &tag,
    );

    assert!(
        matches!(result, Err(AeadError::Core(AeadCoreError::Injected))),
        "a refused decrypt came back as {result:?}"
    );

    Ok(())
}

#[test]
fn test_decrypt_refuses_invalid_inputs_for_xchacha_variant() {
    let aead = Aead::from_algorithm(AeadAlgorithm::XChachaPoly1305);

    for given in every_width_but(chacha::KEY_SIZE) {
        let mut data = filled(64);

        let result = aead.decrypt(
            &filled(given),
            &filled(chacha::XNONCE_SIZE),
            b"",
            &mut data,
            &filled(poly1305::TAG_SIZE),
        );

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::XChachaPoly1305,
            chacha::KEY_SIZE,
            given,
            "a key"
        );
    }

    for given in every_width_but(chacha::XNONCE_SIZE) {
        let mut data = filled(64);

        let result = aead.decrypt(
            &filled(chacha::KEY_SIZE),
            &filled(given),
            b"",
            &mut data,
            &filled(poly1305::TAG_SIZE),
        );

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::XChachaPoly1305,
            chacha::XNONCE_SIZE,
            given,
            "a nonce"
        );
    }

    for given in every_width_but(poly1305::TAG_SIZE) {
        let mut data = filled(64);

        let result = aead.decrypt(
            &filled(chacha::KEY_SIZE),
            &filled(chacha::XNONCE_SIZE),
            b"",
            &mut data,
            &filled(given),
        );

        assert_width!(
            result,
            TagWidth,
            AeadAlgorithm::XChachaPoly1305,
            poly1305::TAG_SIZE,
            given,
            "a tag"
        );
    }
}

#[test]
#[cfg(aes_asm)]
fn test_decrypt_refuses_invalid_inputs_for_aegis_variant() {
    let aead = Aead::from_algorithm(AeadAlgorithm::Aegis128L);

    for given in every_width_but(aegis::KEY_SIZE) {
        let mut data = filled(64);

        let result = aead.decrypt(
            &filled(given),
            &filled(aegis::NONCE_SIZE),
            b"",
            &mut data,
            &filled(aegis::TAG_SIZE),
        );

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::Aegis128L,
            aegis::KEY_SIZE,
            given,
            "a key"
        );
    }

    for given in every_width_but(aegis::NONCE_SIZE) {
        let mut data = filled(64);

        let result = aead.decrypt(
            &filled(aegis::KEY_SIZE),
            &filled(given),
            b"",
            &mut data,
            &filled(aegis::TAG_SIZE),
        );

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::Aegis128L,
            aegis::NONCE_SIZE,
            given,
            "a nonce"
        );
    }

    for given in every_width_but(aegis::TAG_SIZE) {
        let mut data = filled(64);

        let result = aead.decrypt(
            &filled(aegis::KEY_SIZE),
            &filled(aegis::NONCE_SIZE),
            b"",
            &mut data,
            &filled(given),
        );

        assert_width!(
            result,
            TagWidth,
            AeadAlgorithm::Aegis128L,
            aegis::TAG_SIZE,
            given,
            "a tag"
        );
    }
}

/// A tag the key never wrote does not open the message.
///
/// The width fits, so nothing this crate measures refuses it: what comes back
/// is the cipher's own answer, carried out through the facade.
#[test]
fn test_decrypt_propagates_a_tag_mismatch_for_xchacha_variant() {
    let key = filled(chacha::KEY_SIZE);
    let nonce = filled(chacha::XNONCE_SIZE);
    let mut data = filled(64);
    let tag = filled(poly1305::TAG_SIZE);

    let result = Aead::from_algorithm(AeadAlgorithm::XChachaPoly1305)
        .decrypt(&key, &nonce, b"", &mut data, &tag);

    assert_eq!(
        result,
        Err(AeadError::Core(AeadCoreError::AuthenticationFailed))
    );
}

#[test]
#[cfg(aes_asm)]
fn test_decrypt_propagates_a_tag_mismatch_for_aegis_variant() {
    let key = filled(aegis::KEY_SIZE);
    let nonce = filled(aegis::NONCE_SIZE);
    let mut data = filled(64);
    let tag = filled(aegis::TAG_SIZE);

    let result =
        Aead::from_algorithm(AeadAlgorithm::Aegis128L).decrypt(&key, &nonce, b"", &mut data, &tag);

    assert_eq!(
        result,
        Err(AeadError::Core(AeadCoreError::AuthenticationFailed))
    );
}

proptest! {
    /// What the facade opens is what the cipher opens, and it refuses where the
    /// cipher refuses.
    ///
    /// The message is sealed by the cipher directly, so what is asked of the
    /// facade is only whether it reaches the same one with the same arguments.
    #[test]
    fn test_decrypt_answers_what_xchacha_answers(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform24(any::<u8>()),
        aad in prop::collection::vec(any::<u8>(), 0..96),
        message in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut sealed = message.clone();
        let mut tag = [0_u8; poly1305::TAG_SIZE];

        XChaCha20Poly1305::new().encrypt(&key, &nonce, &aad, &mut sealed, &mut tag);

        let mut through = sealed.clone();

        Aead::from_algorithm(AeadAlgorithm::XChachaPoly1305)
            .decrypt(&key, &nonce, &aad, &mut through, &tag)?;

        let mut direct = sealed.clone();

        XChaCha20Poly1305::new()
            .decrypt(&key, &nonce, &aad, &mut direct, &tag)
            .map_err(|why| TestCaseError::fail(alloc::format!("{why}")))?;

        prop_assert_eq!(&through, &direct);
        prop_assert_eq!(&through, &message);
    }
}

#[cfg(aes_asm)]
proptest! {
    #[test]
    fn test_decrypt_answers_what_aegis_answers(
        key in prop::array::uniform16(any::<u8>()),
        nonce in prop::array::uniform16(any::<u8>()),
        aad in prop::collection::vec(any::<u8>(), 0..96),
        message in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut sealed = message.clone();
        let mut tag = [0_u8; aegis::TAG_SIZE];

        Aegis128L::new().encrypt(&key, &nonce, &aad, &mut sealed, &mut tag);

        let mut through = sealed.clone();

        Aead::from_algorithm(AeadAlgorithm::Aegis128L)
            .decrypt(&key, &nonce, &aad, &mut through, &tag)?;

        let mut direct = sealed.clone();

        Aegis128L::new()
            .decrypt(&key, &nonce, &aad, &mut direct, &tag)
            .map_err(|why| TestCaseError::fail(alloc::format!("{why}")))?;

        prop_assert_eq!(&through, &direct);
        prop_assert_eq!(&through, &message);
    }
}

proptest! {
    /// A tag the key never wrote is refused, through the facade as under it.
    #[test]
    fn test_decrypt_refuses_a_tag_that_sealed_nothing_for_xchacha(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform24(any::<u8>()),
        tag in prop::array::uniform16(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let mut through = message.clone();

        let refused = Aead::from_algorithm(AeadAlgorithm::XChachaPoly1305)
            .decrypt(&key, &nonce, b"", &mut through, &tag);

        let mut direct = message.clone();

        let underneath = XChaCha20Poly1305::new().decrypt(&key, &nonce, b"", &mut direct, &tag);

        prop_assert_eq!(refused.is_err(), underneath.is_err());
        prop_assert_eq!(&through, &direct);
    }
}
