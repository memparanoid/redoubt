// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_aead_core::AeadError as AeadCoreError;
use redoubt_rand::EntropyError;

use crate::enums::AeadBehaviour;
use crate::errors::AeadError;
use crate::support::test_utils::Fuse;

/// What a sealing or an opening is refused with: the shape either fails in for
/// real, carrying the marker that says a test put it there.
macro_rules! assert_injected {
    ($result:expr) => {{
        let got = $result;

        assert!(
            matches!(got, Err(AeadError::Primitive(AeadCoreError::Injected))),
            "expected a refusal, got {got:?}"
        );
    }};
}

/// What a nonce is refused with, which is the shape a machine with no
/// randomness answers with.
macro_rules! assert_no_nonce {
    ($result:expr) => {{
        let got = $result;

        assert!(
            matches!(got, Err(AeadError::NonceEntropy(EntropyError::Injected))),
            "expected no nonce, got {got:?}"
        );
    }};
}

macro_rules! assert_passes {
    ($result:expr, $said:literal) => {{
        let got = $result;

        assert!(got.is_ok(), concat!($said, ": {:?}"), got);
    }};
}

// === === === === === === === === === ===
// at_encrypt
// === === === === === === === === === ===

#[test]
fn test_at_encrypt_reports_injected_at_the_first_call() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(1));

    assert_injected!(fuse.at_encrypt());
}

#[test]
fn test_at_encrypt_reports_injected_at_the_nth_call() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(3));

    assert_passes!(fuse.at_encrypt(), "the first call");
    assert_passes!(fuse.at_encrypt(), "the second call");

    assert_injected!(fuse.at_encrypt());
}

#[test]
fn test_at_encrypt_lets_the_calls_after_the_nth_through() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(1));

    assert_injected!(fuse.at_encrypt());

    assert_passes!(fuse.at_encrypt(), "the call after the one that was refused");
}

#[test]
fn test_at_encrypt_lets_another_operations_behaviour_through() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthDecrypt(1));

    assert_passes!(fuse.at_encrypt(), "an encrypt under a decrypt behaviour");
}

// === === === === === === === === === ===
// at_decrypt
// === === === === === === === === === ===

#[test]
fn test_at_decrypt_reports_injected_at_the_first_call() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthDecrypt(1));

    assert_injected!(fuse.at_decrypt());
}

#[test]
fn test_at_decrypt_reports_injected_at_the_nth_call() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthDecrypt(3));

    assert_passes!(fuse.at_decrypt(), "the first call");
    assert_passes!(fuse.at_decrypt(), "the second call");

    assert_injected!(fuse.at_decrypt());
}

#[test]
fn test_at_decrypt_lets_the_calls_after_the_nth_through() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthDecrypt(1));

    assert_injected!(fuse.at_decrypt());

    assert_passes!(fuse.at_decrypt(), "the call after the one that was refused");
}

#[test]
fn test_at_decrypt_lets_another_operations_behaviour_through() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(1));

    assert_passes!(fuse.at_decrypt(), "a decrypt under an encrypt behaviour");
}

// === === === === === === === === === ===
// at_generate_nonce
// === === === === === === === === === ===

#[test]
fn test_at_generate_nonce_reports_injected_at_the_first_call() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthGenerateNonce(1));

    assert_no_nonce!(fuse.at_generate_nonce());
}

#[test]
fn test_at_generate_nonce_reports_injected_at_the_nth_call() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthGenerateNonce(3));

    assert_passes!(fuse.at_generate_nonce(), "the first call");
    assert_passes!(fuse.at_generate_nonce(), "the second call");

    assert_no_nonce!(fuse.at_generate_nonce());
}

#[test]
fn test_at_generate_nonce_lets_the_calls_after_the_nth_through() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthGenerateNonce(1));

    assert_no_nonce!(fuse.at_generate_nonce());

    assert_passes!(
        fuse.at_generate_nonce(),
        "the call after the one that was refused"
    );
}

#[test]
fn test_at_generate_nonce_lets_another_operations_behaviour_through() {
    let fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(1));

    assert_passes!(
        fuse.at_generate_nonce(),
        "a generate_nonce under an encrypt behaviour"
    );
}
