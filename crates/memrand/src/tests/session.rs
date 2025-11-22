// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;
use crate::session::XNonceSessionGenerator;
use crate::support::test_utils::{MockEntropySource, MockEntropySourceBehaviour};
use crate::system::SystemEntropySource;
use crate::traits::XNonceGenerator;

#[test]
fn test_xnonce_session_generator_counter_increments() {
    let entropy = SystemEntropySource {};
    let mut session = XNonceSessionGenerator::new(&entropy);
    let mut xnonce = [0u8; 24];

    // Counter at: 0
    {
        session
            .fill_current_xnonce(&mut xnonce)
            .expect("Failed to fill_current_xnonce() (#0)");
        // Counter part (last 8 bytes) should increment
        let counter = u64::from_le_bytes(xnonce[16..24].try_into().unwrap());

        assert_eq!(counter, 0);
    }

    // Counter at: 1
    {
        session
            .fill_current_xnonce(&mut xnonce)
            .expect("Failed to fill_current_xnonce() (#0)");
        // Counter part (last 8 bytes) should increment
        let counter = u64::from_le_bytes(xnonce[16..24].try_into().unwrap());

        assert_eq!(counter, 1);
    }

    // Counter at: 2
    {
        session
            .fill_current_xnonce(&mut xnonce)
            .expect("Failed to fill_current_xnonce() (#0)");
        // Counter part (last 8 bytes) should increment
        let counter = u64::from_le_bytes(xnonce[16..24].try_into().unwrap());

        assert_eq!(counter, 2);
    }
}

#[test]
fn test_xnonce_session_generator_counter_wraps() {
    let entropy = SystemEntropySource {};
    let mut session = XNonceSessionGenerator::new(&entropy);
    let mut xnonce = [0u8; 24];

    // Set counter to u64::MAX - 1
    session.set_counter_for_test(u64::MAX - 1);

    // Counter at: u64::MAX - 1
    {
        session
            .fill_current_xnonce(&mut xnonce)
            .expect("Failed to fill_current_xnonce() (#0)");
        // Counter part (last 8 bytes) should increment
        let counter = u64::from_le_bytes(xnonce[16..24].try_into().unwrap());

        assert_eq!(counter, u64::MAX - 1);
    }

    // Counter at: counter = u64::MAX
    {
        session
            .fill_current_xnonce(&mut xnonce)
            .expect("Failed to fill_current_xnonce() (#0)");
        // Counter part (last 8 bytes) should increment
        let counter = u64::from_le_bytes(xnonce[16..24].try_into().unwrap());

        assert_eq!(counter, u64::MAX);
    }

    // Counter at: 0 (wrapped)
    {
        session
            .fill_current_xnonce(&mut xnonce)
            .expect("Failed to fill_current_xnonce() (#0)");
        // Counter part (last 8 bytes) should increment
        let counter = u64::from_le_bytes(xnonce[16..24].try_into().unwrap());

        assert_eq!(counter, 0);
    }
}

#[test]
fn test_xnonce_session_generator_propagates_entropy_error() {
    let mock_entropy = MockEntropySource::new(MockEntropySourceBehaviour::FailAtFillBytes);
    let mut session = XNonceSessionGenerator::new(&mock_entropy);
    let mut xnonce = [0u8; 24];

    let result = session.fill_current_xnonce(&mut xnonce);

    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
}
