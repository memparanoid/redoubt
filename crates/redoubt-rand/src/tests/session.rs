// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::mem::size_of;

use crate::error::EntropyError;
use crate::session::{Counter, NonceSessionGenerator, NonceSessionGeneratorBehaviour};
use crate::support::test_utils::{MockEntropySource, MockEntropySourceBehaviour};
use crate::traits::NonceGenerator;

// NonceSessionGeneratorBehaviour

/// A `#[default]` that moved would leave everything constructed without a
/// behaviour injecting a failure instead of nothing.
#[test]
fn test_behaviour_default_returns_none() {
    assert_eq!(
        NonceSessionGeneratorBehaviour::default(),
        NonceSessionGeneratorBehaviour::None
    );
}

// NonceSessionGenerator

#[test]
fn test_nonce_session_generator_counter_increments() -> Result<(), Box<dyn std::error::Error>> {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::None);

    let mut session = NonceSessionGenerator::<_, 16>::new(entropy);
    session.set_counter_for_test(0);

    // Counter at: 0
    {
        let nonce = session.generate_nonce()?;
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(nonce[0..size_of::<Counter>()].try_into()?);

        assert_eq!(counter, 0);
    }

    // Counter at: 1
    {
        let nonce = session.generate_nonce()?;
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(nonce[0..size_of::<Counter>()].try_into()?);

        assert_eq!(counter, 1);
    }

    // Counter at: 2
    {
        let nonce = session.generate_nonce()?;
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(nonce[0..size_of::<Counter>()].try_into()?);

        assert_eq!(counter, 2);
    }

    Ok(())
}

#[test]
fn test_nonce_session_generator_counter_wraps() -> Result<(), Box<dyn std::error::Error>> {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut session = NonceSessionGenerator::<_, 16>::new(entropy);

    // Set counter to Counter::MAX - 1
    session.set_counter_for_test(Counter::MAX - 1);

    // Counter at: Counter::MAX - 1
    {
        let nonce = session.generate_nonce()?;
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(nonce[0..size_of::<Counter>()].try_into()?);

        assert_eq!(counter, Counter::MAX - 1);
    }

    // Counter at: Counter::MAX
    {
        let nonce = session.generate_nonce()?;
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(nonce[0..size_of::<Counter>()].try_into()?);

        assert_eq!(counter, Counter::MAX);
    }

    // Counter at: 0 (wrapped)
    {
        let nonce = session.generate_nonce()?;
        // Counter part (first bytes) should increment
        let counter = Counter::from_le_bytes(nonce[0..size_of::<Counter>()].try_into()?);

        assert_eq!(counter, 0);
    }

    Ok(())
}

#[test]
fn test_nonce_session_generator_fail_at_generate_nonce_behaviour() {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut session = NonceSessionGenerator::<_, 16>::new(entropy)
        .with_behaviour(NonceSessionGeneratorBehaviour::FailAtGenerateNonce);

    let result = session.generate_nonce();

    assert!(matches!(result, Err(EntropyError::Injected)));
}

/// The check sits before `maybe_initialize`, so an injected failure costs no
/// entropy and leaves the counter uninitialized.
#[test]
fn test_nonce_session_generator_fail_at_generate_nonce_behaviour_asks_no_entropy() {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut session = NonceSessionGenerator::<_, 16>::new(entropy)
        .with_behaviour(NonceSessionGeneratorBehaviour::FailAtGenerateNonce);

    let result = session.generate_nonce();

    assert!(matches!(result, Err(EntropyError::Injected)));
    assert_eq!(session.entropy().call_count(), 0);
}

#[test]
fn test_nonce_session_generator_none_behaviour() {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut session = NonceSessionGenerator::<_, 16>::new(entropy)
        .with_behaviour(NonceSessionGeneratorBehaviour::None);

    let result = session.generate_nonce();

    assert!(
        result.is_ok(),
        "a generator with nothing injected gave no nonce: {result:?}"
    );
}

#[test]
fn test_nonce_session_generator_propagates_maybe_initialize_error() {
    let mock_entropy = MockEntropySource::new(MockEntropySourceBehaviour::FailAtNthFillBytes(1));
    let mut session = NonceSessionGenerator::<_, 16>::new(mock_entropy);

    let result = session.generate_nonce();

    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
}

#[test]
fn test_nonce_session_generator_propagates_entropy_error() {
    let mock_entropy = MockEntropySource::new(MockEntropySourceBehaviour::FailAtNthFillBytes(2));
    let mut session = NonceSessionGenerator::<_, 16>::new(mock_entropy);

    let result = session.generate_nonce();

    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
}
