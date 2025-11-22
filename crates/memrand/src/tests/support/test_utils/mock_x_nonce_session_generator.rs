// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::SystemEntropySource;
use crate::error::EntropyError;
use crate::support::test_utils::{MockXNonceGeneratorBehaviour, MockXNonceSessionGenerator};
use crate::traits::XNonceGenerator;

#[test]
fn test_mock_xnonce_generator_behaviour_none() {
    let entropy = SystemEntropySource {};
    let mut mock = MockXNonceSessionGenerator::new(&entropy, MockXNonceGeneratorBehaviour::None);

    let mut xnonce = [0u8; 24];
    let result = mock.fill_current_xnonce(&mut xnonce);

    assert!(result.is_ok());
}

#[test]
fn test_mock_xnonce_generator_behaviour_fail_at_fill_bytes() {
    let entropy = SystemEntropySource {};
    let mut mock =
        MockXNonceSessionGenerator::new(&entropy, MockXNonceGeneratorBehaviour::FailAtFillBytes);

    let mut nonce = [0u8; 24];
    let result = mock.fill_current_xnonce(&mut nonce);

    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
}

#[test]
fn test_mock_xnonce_generator_change_behaviour() {
    let entropy = SystemEntropySource {};
    let mut mock = MockXNonceSessionGenerator::new(&entropy, MockXNonceGeneratorBehaviour::None);

    let mut xnonce = [0u8; 24];

    // First works
    assert!(mock.fill_current_xnonce(&mut xnonce).is_ok());

    // Change behaviour
    mock.change_behaviour(MockXNonceGeneratorBehaviour::FailAtFillBytes);

    // Now fails
    assert!(mock.fill_current_xnonce(&mut xnonce).is_err());

    // Change back
    mock.change_behaviour(MockXNonceGeneratorBehaviour::None);

    // Works again
    assert!(mock.fill_current_xnonce(&mut xnonce).is_ok());
}
