// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;
use crate::support::test_utils::{MockEntropySource, MockEntropySourceBehaviour};
use crate::traits::EntropySource;

#[test]
fn test_mock_entropy_source_behaviour_none() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut buf = [0u8; 32];

    let result = mock.fill_bytes(&mut buf);

    assert!(result.is_ok());
}

#[test]
fn test_mock_entropy_source_behaviour_fail_always() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::FailAlways);
    let mut buf = [0u8; 32];

    let result = mock.fill_bytes(&mut buf);

    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
}

#[test]
fn test_mock_entropy_source_behaviour_fail_at_nth_first_call() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::FailAtNthFillBytes(1));
    let mut buf = [0u8; 32];

    // First call fails
    let result = mock.fill_bytes(&mut buf);
    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));

    // Second call succeeds
    let result = mock.fill_bytes(&mut buf);
    assert!(result.is_ok());
}

#[test]
fn test_mock_entropy_source_behaviour_fail_at_nth_third_call() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::FailAtNthFillBytes(3));
    let mut buf = [0u8; 32];

    // First two calls succeed
    assert!(mock.fill_bytes(&mut buf).is_ok());
    assert!(mock.fill_bytes(&mut buf).is_ok());

    // Third call fails
    let result = mock.fill_bytes(&mut buf);
    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));

    // Fourth call succeeds
    assert!(mock.fill_bytes(&mut buf).is_ok());
}

#[test]
fn test_mock_entropy_source_call_count() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut buf = [0u8; 32];

    assert_eq!(mock.call_count(), 0);

    mock.fill_bytes(&mut buf).unwrap();
    assert_eq!(mock.call_count(), 1);

    mock.fill_bytes(&mut buf).unwrap();
    assert_eq!(mock.call_count(), 2);

    mock.reset_count();
    assert_eq!(mock.call_count(), 0);
}

#[test]
fn test_mock_entropy_source_change_behaviour() {
    let mut mock = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut bytes = [0u8; 32];

    // First works
    assert!(mock.fill_bytes(&mut bytes).is_ok());

    // Change behaviour
    mock.change_behaviour(MockEntropySourceBehaviour::FailAlways);

    // Now fails
    assert!(mock.fill_bytes(&mut bytes).is_err());

    // Change back
    mock.change_behaviour(MockEntropySourceBehaviour::None);

    // Works again
    assert!(mock.fill_bytes(&mut bytes).is_ok());
}
