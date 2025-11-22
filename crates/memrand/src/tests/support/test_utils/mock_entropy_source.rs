// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::SystemEntropySource;
use crate::error::EntropyError;
use crate::support::test_utils::{
    MockEntropySource, MockEntropySourceBehaviour, MockXNonceGeneratorBehaviour,
    MockXNonceSessionGenerator,
};
use crate::traits::{EntropySource, XNonceGenerator};

#[test]
fn test_mock_entropy_source_behaviour_none() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut buf = [0u8; 32];

    let result = mock.fill_bytes(&mut buf);

    assert!(result.is_ok());
}

#[test]
fn test_mock_entropy_source_behaviour_fail_at_fill_bytes() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::FailAtFillBytes);
    let mut buf = [0u8; 32];

    let result = mock.fill_bytes(&mut buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
}

#[test]
fn test_mock_entropy_source_change_behaviour() {
    let mut mock = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut bytes = [0u8; 32];

    // First works
    assert!(mock.fill_bytes(&mut bytes).is_ok());

    // Change behaviour
    mock.change_behaviour(MockEntropySourceBehaviour::FailAtFillBytes);

    // Now fails
    assert!(mock.fill_bytes(&mut bytes).is_err());

    // Change back
    mock.change_behaviour(MockEntropySourceBehaviour::None);

    // Works again
    assert!(mock.fill_bytes(&mut bytes).is_ok());
}
