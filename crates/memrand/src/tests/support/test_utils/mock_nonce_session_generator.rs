// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::SystemEntropySource;
use crate::error::EntropyError;
use crate::support::test_utils::{MockNonceSessionGenerator, MockNonceSessionGeneratorBehaviour};
use crate::traits::NonceGenerator;

#[test]
fn test_mock_nonce_generator_behaviour_none() {
    let entropy = SystemEntropySource {};
    let mut mock =
        MockNonceSessionGenerator::<24>::new(&entropy, MockNonceSessionGeneratorBehaviour::None);

    let result = mock.generate_nonce();

    assert!(result.is_ok());
}

#[test]
fn test_mock_nonce_generator_behaviour_fail_at_fill_bytes() {
    let entropy = SystemEntropySource {};
    let mut mock = MockNonceSessionGenerator::<24>::new(
        &entropy,
        MockNonceSessionGeneratorBehaviour::FailAtFillBytes,
    );

    let result = mock.generate_nonce();

    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
}

#[test]
fn test_mock_nonce_generator_change_behaviour() {
    let entropy = SystemEntropySource {};
    let mut mock =
        MockNonceSessionGenerator::<24>::new(&entropy, MockNonceSessionGeneratorBehaviour::None);

    // First works
    assert!(mock.generate_nonce().is_ok());

    // Change behaviour
    mock.change_behaviour(MockNonceSessionGeneratorBehaviour::FailAtFillBytes);

    // Now fails
    assert!(mock.generate_nonce().is_err());

    // Change back
    mock.change_behaviour(MockNonceSessionGeneratorBehaviour::None);

    // Works again
    assert!(mock.generate_nonce().is_ok());
}
