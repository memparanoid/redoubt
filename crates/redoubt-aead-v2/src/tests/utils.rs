// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use alloc::vec::Vec;

use redoubt_aead_v2_core::consts::{aegis, chacha, poly1305};

use crate::enums::AeadAlgorithm;
use crate::errors::AeadError;
use crate::utils::{aegis_widths, aegis_widths_mut, chacha_widths, chacha_widths_mut};

const CHACHA_KEY: usize = chacha::KEY_SIZE;
const CHACHA_NONCE: usize = chacha::XNONCE_SIZE;
const CHACHA_TAG: usize = poly1305::TAG_SIZE;

const AEGIS_KEY: usize = aegis::KEY_SIZE;
const AEGIS_NONCE: usize = aegis::NONCE_SIZE;
const AEGIS_TAG: usize = aegis::TAG_SIZE;

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


/// The error a set of widths draws, with the buffers owned here so that what
/// comes back borrows nothing.
fn chacha_case(key: usize, nonce: usize, tag: usize) -> Option<AeadError> {
    let (key, nonce, tag) = (filled(key), filled(nonce), filled(tag));

    chacha_widths(&key, &nonce, &tag).err()
}

fn chacha_case_mut(key: usize, nonce: usize, tag: usize) -> Option<AeadError> {
    let (key, nonce, mut tag) = (filled(key), filled(nonce), filled(tag));

    chacha_widths_mut(&key, &nonce, &mut tag).err()
}

fn aegis_case(key: usize, nonce: usize, tag: usize) -> Option<AeadError> {
    let (key, nonce, tag) = (filled(key), filled(nonce), filled(tag));

    aegis_widths(&key, &nonce, &tag).err()
}

fn aegis_case_mut(key: usize, nonce: usize, tag: usize) -> Option<AeadError> {
    let (key, nonce, mut tag) = (filled(key), filled(nonce), filled(tag));

    aegis_widths_mut(&key, &nonce, &mut tag).err()
}

/// The three fields, so that a width reported against the wrong cipher, or with
/// the wrong number in either place, is a failure rather than a pass.
macro_rules! assert_width {
    ($result:expr, $variant:ident, $algorithm:expr, $expected:expr, $given:expr, $said:literal) => {
        assert!(
            matches!(
                $result,
                Some(AeadError::$variant {
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

// === === === === === === === === === ===
// chacha_widths
// === === === === === === === === === ===

#[test]
fn test_chacha_widths_reports_every_key_width_that_is_not_its_own() {
    for given in every_width_but(CHACHA_KEY) {
        let result = chacha_case(given, CHACHA_NONCE, CHACHA_TAG);

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::XChachaPoly1305,
            CHACHA_KEY,
            given,
            "a key"
        );
    }
}

#[test]
fn test_chacha_widths_reports_every_nonce_width_that_is_not_its_own() {
    for given in every_width_but(CHACHA_NONCE) {
        let result = chacha_case(CHACHA_KEY, given, CHACHA_TAG);

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::XChachaPoly1305,
            CHACHA_NONCE,
            given,
            "a nonce"
        );
    }
}

#[test]
fn test_chacha_widths_reports_every_tag_width_that_is_not_its_own() {
    for given in every_width_but(CHACHA_TAG) {
        let result = chacha_case(CHACHA_KEY, CHACHA_NONCE, given);

        assert_width!(
            result,
            TagWidth,
            AeadAlgorithm::XChachaPoly1305,
            CHACHA_TAG,
            given,
            "a tag"
        );
    }
}

/// The key is measured first, whatever else is also wrong.
///
/// A caller fixes what it is told about and calls again. Told about the tag
/// while the key was also wrong, it would fix the tag and be told the same
/// thing over.
#[test]
fn test_chacha_widths_reports_the_key_before_the_others() {
    for given in every_width_but(CHACHA_KEY) {
        let result = chacha_case(given, 0, 0);

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::XChachaPoly1305,
            CHACHA_KEY,
            given,
            "a key"
        );
    }
}

/// The nonce is measured before the tag, once the key fits.
#[test]
fn test_chacha_widths_reports_the_nonce_before_the_tag() {
    for given in every_width_but(CHACHA_NONCE) {
        let result = chacha_case(CHACHA_KEY, given, 0);

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::XChachaPoly1305,
            CHACHA_NONCE,
            given,
            "a nonce"
        );
    }
}

/// What comes back points at the caller's own bytes.
///
/// `<&[u8; N]>::try_from` reads a length and borrows; the owning form would
/// copy, and a copy of a key is a second one nothing here can empty. A pointer
/// that moved is that copy, and it is the only way to see it from inside the
/// process.
#[test]
fn test_chacha_widths_borrows_rather_than_copies() {
    let key = filled(CHACHA_KEY);
    let nonce = filled(CHACHA_NONCE);
    let tag = filled(CHACHA_TAG);

    let (taken, with, sealed) =
        chacha_widths(&key, &nonce, &tag).expect("Infallible: the widths are the cipher's own");

    assert!(core::ptr::eq(taken.as_ptr(), key.as_ptr()), "the key moved");
    assert!(
        core::ptr::eq(with.as_ptr(), nonce.as_ptr()),
        "the nonce moved"
    );
    assert!(core::ptr::eq(sealed.as_ptr(), tag.as_ptr()), "the tag moved");
}

#[test]
fn test_chacha_widths_answers_with_the_bytes_it_was_handed() {
    let key = filled(CHACHA_KEY);
    let nonce = filled(CHACHA_NONCE);
    let tag = filled(CHACHA_TAG);

    let (taken, with, sealed) =
        chacha_widths(&key, &nonce, &tag).expect("Infallible: the widths are the cipher's own");

    assert_eq!(taken.as_slice(), key.as_slice());
    assert_eq!(with.as_slice(), nonce.as_slice());
    assert_eq!(sealed.as_slice(), tag.as_slice());
}

// === === === === === === === === === ===
// chacha_widths_mut
// === === === === === === === === === ===

#[test]
fn test_chacha_widths_mut_reports_every_key_width_that_is_not_its_own() {
    for given in every_width_but(CHACHA_KEY) {
        let result = chacha_case_mut(given, CHACHA_NONCE, CHACHA_TAG);

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::XChachaPoly1305,
            CHACHA_KEY,
            given,
            "a key"
        );
    }
}

#[test]
fn test_chacha_widths_mut_reports_every_nonce_width_that_is_not_its_own() {
    for given in every_width_but(CHACHA_NONCE) {
        let result = chacha_case_mut(CHACHA_KEY, given, CHACHA_TAG);

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::XChachaPoly1305,
            CHACHA_NONCE,
            given,
            "a nonce"
        );
    }
}

#[test]
fn test_chacha_widths_mut_reports_every_tag_width_that_is_not_its_own() {
    for given in every_width_but(CHACHA_TAG) {
        let result = chacha_case_mut(CHACHA_KEY, CHACHA_NONCE, given);

        assert_width!(
            result,
            TagWidth,
            AeadAlgorithm::XChachaPoly1305,
            CHACHA_TAG,
            given,
            "a tag"
        );
    }
}

#[test]
fn test_chacha_widths_mut_borrows_rather_than_copies() {
    let key = filled(CHACHA_KEY);
    let nonce = filled(CHACHA_NONCE);
    let mut tag = filled(CHACHA_TAG);
    let at = tag.as_ptr();

    let (taken, with, sealed) = chacha_widths_mut(&key, &nonce, &mut tag)
        .expect("Infallible: the widths are the cipher's own");

    assert!(core::ptr::eq(taken.as_ptr(), key.as_ptr()), "the key moved");
    assert!(
        core::ptr::eq(with.as_ptr(), nonce.as_ptr()),
        "the nonce moved"
    );
    assert!(core::ptr::eq(sealed.as_ptr(), at), "the tag moved");
}

/// What is written through the tag reaches the caller's buffer.
///
/// The borrow is what makes the cipher's answer land where the caller will read
/// it; a copy would take the write and leave the buffer as it was.
#[test]
fn test_chacha_widths_mut_writes_through_to_the_caller() {
    let key = filled(CHACHA_KEY);
    let nonce = filled(CHACHA_NONCE);
    let mut tag = filled(CHACHA_TAG);

    {
        let (_, _, sealed) = chacha_widths_mut(&key, &nonce, &mut tag)
            .expect("Infallible: the widths are the cipher's own");

        sealed.fill(0xc3);
    }

    assert!(tag.iter().all(|byte| *byte == 0xc3));
}

// === === === === === === === === === ===
// aegis_widths
// === === === === === === === === === ===

#[test]
fn test_aegis_widths_reports_every_key_width_that_is_not_its_own() {
    for given in every_width_but(AEGIS_KEY) {
        let result = aegis_case(given, AEGIS_NONCE, AEGIS_TAG);

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::Aegis128L,
            AEGIS_KEY,
            given,
            "a key"
        );
    }
}

#[test]
fn test_aegis_widths_reports_every_nonce_width_that_is_not_its_own() {
    for given in every_width_but(AEGIS_NONCE) {
        let result = aegis_case(AEGIS_KEY, given, AEGIS_TAG);

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::Aegis128L,
            AEGIS_NONCE,
            given,
            "a nonce"
        );
    }
}

#[test]
fn test_aegis_widths_reports_every_tag_width_that_is_not_its_own() {
    for given in every_width_but(AEGIS_TAG) {
        let result = aegis_case(AEGIS_KEY, AEGIS_NONCE, given);

        assert_width!(
            result,
            TagWidth,
            AeadAlgorithm::Aegis128L,
            AEGIS_TAG,
            given,
            "a tag"
        );
    }
}

#[test]
fn test_aegis_widths_reports_the_key_before_the_others() {
    for given in every_width_but(AEGIS_KEY) {
        let result = aegis_case(given, 0, 0);

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::Aegis128L,
            AEGIS_KEY,
            given,
            "a key"
        );
    }
}

#[test]
fn test_aegis_widths_reports_the_nonce_before_the_tag() {
    for given in every_width_but(AEGIS_NONCE) {
        let result = aegis_case(AEGIS_KEY, given, 0);

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::Aegis128L,
            AEGIS_NONCE,
            given,
            "a nonce"
        );
    }
}

#[test]
fn test_aegis_widths_borrows_rather_than_copies() {
    let key = filled(AEGIS_KEY);
    let nonce = filled(AEGIS_NONCE);
    let tag = filled(AEGIS_TAG);

    let (taken, with, sealed) =
        aegis_widths(&key, &nonce, &tag).expect("Infallible: the widths are the cipher's own");

    assert!(core::ptr::eq(taken.as_ptr(), key.as_ptr()), "the key moved");
    assert!(
        core::ptr::eq(with.as_ptr(), nonce.as_ptr()),
        "the nonce moved"
    );
    assert!(core::ptr::eq(sealed.as_ptr(), tag.as_ptr()), "the tag moved");
}

#[test]
fn test_aegis_widths_answers_with_the_bytes_it_was_handed() {
    let key = filled(AEGIS_KEY);
    let nonce = filled(AEGIS_NONCE);
    let tag = filled(AEGIS_TAG);

    let (taken, with, sealed) =
        aegis_widths(&key, &nonce, &tag).expect("Infallible: the widths are the cipher's own");

    assert_eq!(taken.as_slice(), key.as_slice());
    assert_eq!(with.as_slice(), nonce.as_slice());
    assert_eq!(sealed.as_slice(), tag.as_slice());
}

// === === === === === === === === === ===
// aegis_widths_mut
// === === === === === === === === === ===

#[test]
fn test_aegis_widths_mut_reports_every_key_width_that_is_not_its_own() {
    for given in every_width_but(AEGIS_KEY) {
        let result = aegis_case_mut(given, AEGIS_NONCE, AEGIS_TAG);

        assert_width!(
            result,
            KeyWidth,
            AeadAlgorithm::Aegis128L,
            AEGIS_KEY,
            given,
            "a key"
        );
    }
}

#[test]
fn test_aegis_widths_mut_reports_every_nonce_width_that_is_not_its_own() {
    for given in every_width_but(AEGIS_NONCE) {
        let result = aegis_case_mut(AEGIS_KEY, given, AEGIS_TAG);

        assert_width!(
            result,
            NonceWidth,
            AeadAlgorithm::Aegis128L,
            AEGIS_NONCE,
            given,
            "a nonce"
        );
    }
}

#[test]
fn test_aegis_widths_mut_reports_every_tag_width_that_is_not_its_own() {
    for given in every_width_but(AEGIS_TAG) {
        let result = aegis_case_mut(AEGIS_KEY, AEGIS_NONCE, given);

        assert_width!(
            result,
            TagWidth,
            AeadAlgorithm::Aegis128L,
            AEGIS_TAG,
            given,
            "a tag"
        );
    }
}

#[test]
fn test_aegis_widths_mut_borrows_rather_than_copies() {
    let key = filled(AEGIS_KEY);
    let nonce = filled(AEGIS_NONCE);
    let mut tag = filled(AEGIS_TAG);
    let at = tag.as_ptr();

    let (taken, with, sealed) = aegis_widths_mut(&key, &nonce, &mut tag)
        .expect("Infallible: the widths are the cipher's own");

    assert!(core::ptr::eq(taken.as_ptr(), key.as_ptr()), "the key moved");
    assert!(
        core::ptr::eq(with.as_ptr(), nonce.as_ptr()),
        "the nonce moved"
    );
    assert!(core::ptr::eq(sealed.as_ptr(), at), "the tag moved");
}

#[test]
fn test_aegis_widths_mut_writes_through_to_the_caller() {
    let key = filled(AEGIS_KEY);
    let nonce = filled(AEGIS_NONCE);
    let mut tag = filled(AEGIS_TAG);

    {
        let (_, _, sealed) = aegis_widths_mut(&key, &nonce, &mut tag)
            .expect("Infallible: the widths are the cipher's own");

        sealed.fill(0xc3);
    }

    assert!(tag.iter().all(|byte| *byte == 0xc3));
}

// === === === === === === === === === ===
// What one cipher's widths are to the other
// === === === === === === === === === ===

/// A caller that reached for the wrong pair is told which cipher was measuring.
///
/// AEGIS takes sixteen bytes of key where XChaCha takes thirty-two, so "the key
/// is the wrong size" would leave the caller to work out which was asking.
#[test]
fn test_neither_cipher_takes_the_other_key() {
    let chacha = chacha_case(AEGIS_KEY, CHACHA_NONCE, CHACHA_TAG);
    let aegis = aegis_case(CHACHA_KEY, AEGIS_NONCE, AEGIS_TAG);

    assert_width!(
        chacha,
        KeyWidth,
        AeadAlgorithm::XChachaPoly1305,
        CHACHA_KEY,
        AEGIS_KEY,
        "a key"
    );
    assert_width!(
        aegis,
        KeyWidth,
        AeadAlgorithm::Aegis128L,
        AEGIS_KEY,
        CHACHA_KEY,
        "a key"
    );
}

#[test]
fn test_neither_cipher_takes_the_other_nonce() {
    let chacha = chacha_case(CHACHA_KEY, AEGIS_NONCE, CHACHA_TAG);
    let aegis = aegis_case(AEGIS_KEY, CHACHA_NONCE, AEGIS_TAG);

    assert_width!(
        chacha,
        NonceWidth,
        AeadAlgorithm::XChachaPoly1305,
        CHACHA_NONCE,
        AEGIS_NONCE,
        "a nonce"
    );
    assert_width!(
        aegis,
        NonceWidth,
        AeadAlgorithm::Aegis128L,
        AEGIS_NONCE,
        CHACHA_NONCE,
        "a nonce"
    );
}

/// The tag is the one width they agree on, so a tag is never the thing that
/// tells a caller it reached for the wrong cipher.
#[test]
fn test_both_ciphers_write_a_tag_of_the_same_width() {
    assert_eq!(CHACHA_TAG, AEGIS_TAG);
}
