// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::enums::AeadBehaviour;
use crate::errors::{AeadError, AeadOperation};
use crate::support::test_utils::Fuse;

macro_rules! assert_injected {
    ($result:expr, $operation:expr) => {{
        let got = $result;

        assert!(
            matches!(got, Err(AeadError::Injected(said)) if said == $operation),
            "expected {} to be refused, got {got:?}",
            $operation
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
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(1));

    assert_injected!(fuse.at_encrypt(), AeadOperation::Encrypt);
}

#[test]
fn test_at_encrypt_reports_injected_at_the_nth_call() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(3));

    assert_passes!(fuse.at_encrypt(), "the first call");
    assert_passes!(fuse.at_encrypt(), "the second call");

    assert_injected!(fuse.at_encrypt(), AeadOperation::Encrypt);
}

#[test]
fn test_at_encrypt_lets_the_calls_after_the_nth_through() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(1));

    assert_injected!(fuse.at_encrypt(), AeadOperation::Encrypt);

    assert_passes!(fuse.at_encrypt(), "the call after the one that was refused");
}

#[test]
fn test_at_encrypt_lets_another_operations_behaviour_through() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthDecrypt(1));

    assert_passes!(fuse.at_encrypt(), "an encrypt under a decrypt behaviour");
}

// === === === === === === === === === ===
// at_decrypt
// === === === === === === === === === ===

#[test]
fn test_at_decrypt_reports_injected_at_the_first_call() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthDecrypt(1));

    assert_injected!(fuse.at_decrypt(), AeadOperation::Decrypt);
}

#[test]
fn test_at_decrypt_reports_injected_at_the_nth_call() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthDecrypt(3));

    assert_passes!(fuse.at_decrypt(), "the first call");
    assert_passes!(fuse.at_decrypt(), "the second call");

    assert_injected!(fuse.at_decrypt(), AeadOperation::Decrypt);
}

#[test]
fn test_at_decrypt_lets_the_calls_after_the_nth_through() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthDecrypt(1));

    assert_injected!(fuse.at_decrypt(), AeadOperation::Decrypt);

    assert_passes!(fuse.at_decrypt(), "the call after the one that was refused");
}

#[test]
fn test_at_decrypt_lets_another_operations_behaviour_through() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(1));

    assert_passes!(fuse.at_decrypt(), "a decrypt under an encrypt behaviour");
}

// === === === === === === === === === ===
// at_generate_nonce
// === === === === === === === === === ===

#[test]
fn test_at_generate_nonce_reports_injected_at_the_first_call() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthGenerateNonce(1));

    assert_injected!(fuse.at_generate_nonce(), AeadOperation::GenerateNonce);
}

#[test]
fn test_at_generate_nonce_reports_injected_at_the_nth_call() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthGenerateNonce(3));

    assert_passes!(fuse.at_generate_nonce(), "the first call");
    assert_passes!(fuse.at_generate_nonce(), "the second call");

    assert_injected!(fuse.at_generate_nonce(), AeadOperation::GenerateNonce);
}

#[test]
fn test_at_generate_nonce_lets_the_calls_after_the_nth_through() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthGenerateNonce(1));

    assert_injected!(fuse.at_generate_nonce(), AeadOperation::GenerateNonce);

    assert_passes!(
        fuse.at_generate_nonce(),
        "the call after the one that was refused"
    );
}

#[test]
fn test_at_generate_nonce_lets_another_operations_behaviour_through() {
    let mut fuse = Fuse::new(AeadBehaviour::FailAtNthEncrypt(1));

    assert_passes!(
        fuse.at_generate_nonce(),
        "a generate_nonce under an encrypt behaviour"
    );
}
