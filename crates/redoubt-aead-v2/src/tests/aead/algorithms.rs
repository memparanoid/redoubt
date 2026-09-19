// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::vec;
use alloc::vec::Vec;

use redoubt_codec::DecodeError;

use crate::aead::AeadAlgorithms;
use crate::enums::AeadAlgorithm;

const EVERY: [AeadAlgorithm; 2] = [AeadAlgorithm::XChachaPoly1305, AeadAlgorithm::Aegis128L];

fn set(algorithms: &[AeadAlgorithm]) -> AeadAlgorithms {
    AeadAlgorithms::from(algorithms.to_vec())
}

// === === === === === === === === === ===
// serialize
// === === === === === === === === === ===

#[test]
fn test_serialize_answers_for_a_set_with_nothing_in_it() {
    let mut algorithms = AeadAlgorithms::default();

    assert!(!algorithms.serialize().is_empty());
}

#[test]
fn test_serialize_answers_for_every_size_without_panicking() {
    for size in 0..=EVERY.len() {
        let mut algorithms = set(&EVERY[..size]);

        assert!(!algorithms.serialize().is_empty(), "{size} algorithms");
    }
}

#[test]
fn test_serialize_grows_with_the_number_of_algorithms() {
    let mut none = AeadAlgorithms::default();
    let mut one = set(&EVERY[..1]);
    let mut two = set(&EVERY);

    assert!(none.serialize().len() < one.serialize().len());
    assert!(one.serialize().len() < two.serialize().len());
}

// === === === === === === === === === ===
// deserialize
// === === === === === === === === === ===

/// A collection refuses a short message before it reads anything.
///
/// One algorithm on its own answers `DecodeBufferError`, because what fails is
/// the read. A set answers `PreconditionViolated`, because the header is
/// measured against what arrived before any of it is read.
#[test]
fn test_deserialize_propagates_a_message_with_nothing_in_it() {
    let mut bytes: [u8; 0] = [];

    assert_eq!(
        AeadAlgorithms::deserialize(&mut bytes),
        Err(DecodeError::PreconditionViolated)
    );
}

#[test]
fn test_deserialize_propagates_a_message_cut_short() {
    let mut whole = set(&EVERY).serialize();
    let cut = whole.len() - 1;

    assert!(
        AeadAlgorithms::deserialize(&mut whole[..cut]).is_err(),
        "a message one byte short was accepted"
    );
}

#[test]
fn test_deserialize_propagates_a_byte_that_is_no_algorithm() {
    let mut bytes = set(&EVERY).serialize();
    let last = bytes.len() - 1;
    bytes[last] = 0xff;

    assert_eq!(
        AeadAlgorithms::deserialize(&mut bytes),
        Err(DecodeError::PreconditionViolated)
    );
}

#[test]
fn test_deserialize_propagates_a_byte_that_was_zeroized() {
    let mut bytes = set(&EVERY).serialize();
    let last = bytes.len() - 1;
    bytes[last] = 0;

    assert_eq!(
        AeadAlgorithms::deserialize(&mut bytes),
        Err(DecodeError::PreconditionViolated)
    );
}

#[test]
fn test_deserialize_empties_the_message_when_it_refuses() {
    let mut bytes = set(&EVERY).serialize();
    let last = bytes.len() - 1;
    bytes[last] = 0xff;

    let result = AeadAlgorithms::deserialize(&mut bytes);

    assert_eq!(result, Err(DecodeError::PreconditionViolated));

    // Assert zeroization!
    assert!(bytes.iter().all(|byte| *byte == 0));
}

#[test]
fn test_deserialize_answers_with_the_algorithms_the_message_names() {
    for size in 0..=EVERY.len() {
        let expected = set(&EVERY[..size]);
        let mut bytes = expected.clone().serialize();

        assert_eq!(
            AeadAlgorithms::deserialize(&mut bytes),
            Ok(expected),
            "{size} algorithms"
        );
    }
}

#[test]
fn test_deserialize_keeps_the_order_the_message_had() {
    let backwards = set(&[AeadAlgorithm::Aegis128L, AeadAlgorithm::XChachaPoly1305]);
    let mut bytes = backwards.clone().serialize();

    let read = AeadAlgorithms::deserialize(&mut bytes).expect("Infallible: the message it just wrote");

    assert_eq!(read.as_slice(), backwards.as_slice());
}

// === === === === === === === === === ===
// serialize, then deserialize
// === === === === === === === === === ===

#[test]
fn test_a_set_serialized_and_deserialized_is_the_set_it_was() {
    let expected = set(&EVERY);
    let mut bytes = expected.clone().serialize();

    assert_eq!(AeadAlgorithms::deserialize(&mut bytes), Ok(expected));
}

// === === === === === === === === === ===
// deref
// === === === === === === === === === ===

#[test]
fn test_deref_reaches_the_algorithms_it_was_built_from() {
    let algorithms = set(&EVERY);

    assert_eq!(algorithms.len(), EVERY.len());
    assert_eq!(algorithms.as_slice(), &EVERY);
}

#[test]
fn test_deref_answers_that_it_holds_what_it_holds() {
    let algorithms = set(&EVERY[..1]);

    assert!(algorithms.contains(&AeadAlgorithm::XChachaPoly1305));
    assert!(!algorithms.contains(&AeadAlgorithm::Aegis128L));
}

#[test]
fn test_deref_over_a_set_with_nothing_in_it() {
    let algorithms = AeadAlgorithms::default();

    assert!(algorithms.is_empty());
    assert_eq!(algorithms.iter().count(), 0);
}

// === === === === === === === === === ===
// deref_mut
// === === === === === === === === === ===

#[test]
fn test_deref_mut_adds_an_algorithm_the_set_did_not_have() {
    let mut algorithms = AeadAlgorithms::default();

    algorithms.push(AeadAlgorithm::Aegis128L);

    assert_eq!(algorithms.as_slice(), &[AeadAlgorithm::Aegis128L]);
}

#[test]
fn test_deref_mut_reaches_what_is_serialized() {
    let mut algorithms = AeadAlgorithms::default();
    let empty = algorithms.clone().serialize().len();

    algorithms.push(AeadAlgorithm::Aegis128L);

    assert!(algorithms.serialize().len() > empty);
}

#[test]
fn test_deref_mut_removes_an_algorithm_the_set_had() {
    let mut algorithms = set(&EVERY);

    algorithms.retain(|algorithm| *algorithm != AeadAlgorithm::XChachaPoly1305);

    assert_eq!(algorithms.as_slice(), &[AeadAlgorithm::Aegis128L]);
}

// === === === === === === === === === ===
// From<Vec<AeadAlgorithm>>
// === === === === === === === === === ===

#[test]
fn test_from_keeps_the_vec_it_was_handed() {
    let algorithms: Vec<AeadAlgorithm> = vec![AeadAlgorithm::Aegis128L];

    assert_eq!(
        AeadAlgorithms::from(algorithms.clone()).as_slice(),
        algorithms.as_slice()
    );
}
