// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::mem::size_of;

use crate::error::EntropyError;
use crate::session::{Counter, NonceSessionGenerator};
use crate::support::test_utils::{MockEntropySource, MockEntropySourceBehaviour};
use crate::traits::NonceGenerator;

#[test]
fn test_nonce_session_generator_counter_increments() {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut session = NonceSessionGenerator::<_, 16>::new(entropy);

    // Counter at: 0
    {
        let nonce = session
            .generate_nonce()
            .expect("Failed to generate_nonce() (#0)");
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(
            nonce[0..size_of::<Counter>()]
                .try_into()
                .expect("Failed to convert bytes to Counter"),
        );

        assert_eq!(counter, 0);
    }

    // Counter at: 1
    {
        let nonce = session
            .generate_nonce()
            .expect("Failed to generate_nonce() (#1)");
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(
            nonce[0..size_of::<Counter>()]
                .try_into()
                .expect("Failed to convert bytes to Counter"),
        );

        assert_eq!(counter, 1);
    }

    // Counter at: 2
    {
        let nonce = session
            .generate_nonce()
            .expect("Failed to generate_nonce() (#2)");
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(
            nonce[0..size_of::<Counter>()]
                .try_into()
                .expect("Failed to convert bytes to Counter"),
        );

        assert_eq!(counter, 2);
    }
}

#[test]
fn test_nonce_session_generator_counter_wraps() {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut session = NonceSessionGenerator::<_, 16>::new(entropy);

    // Set counter to Counter::MAX - 1
    session.set_counter_for_test(Counter::MAX - 1);

    // Counter at: Counter::MAX - 1
    {
        let nonce = session
            .generate_nonce()
            .expect("Failed to generate_nonce() (#0)");
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(
            nonce[0..size_of::<Counter>()]
                .try_into()
                .expect("Failed to convert bytes to Counter"),
        );

        assert_eq!(counter, Counter::MAX - 1);
    }

    // Counter at: Counter::MAX
    {
        let nonce = session
            .generate_nonce()
            .expect("Failed to generate_nonce() (#1)");
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(
            nonce[0..size_of::<Counter>()]
                .try_into()
                .expect("Failed to convert bytes to Counter"),
        );

        assert_eq!(counter, Counter::MAX);
    }

    // Counter at: 0 (wrapped)
    {
        let nonce = session
            .generate_nonce()
            .expect("Failed to generate_nonce() (#2)");
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(
            nonce[0..size_of::<Counter>()]
                .try_into()
                .expect("Failed to convert bytes to Counter"),
        );

        assert_eq!(counter, 0);
    }
}

#[test]
fn test_nonce_session_generator_propagates_entropy_error() {
    let mock_entropy = MockEntropySource::new(MockEntropySourceBehaviour::FailAtFillBytes);
    let mut session = NonceSessionGenerator::<_, 16>::new(mock_entropy);

    let result = session.generate_nonce();

    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
}
