// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;
use crate::support::test_utils::{MockEntropySource, MockEntropySourceBehaviour};
use crate::traits::EntropySource;

const STREAM: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

// ============================================================================
// upcoming_backwards
// ============================================================================

#[test]
#[should_panic(expected = "only a mock yielding over a stream")]
fn test_upcoming_backwards_reports_a_mock_with_no_stream() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::None);

    mock.upcoming_backwards(&[4]);
}

#[test]
#[should_panic(expected = "were asked for already")]
fn test_upcoming_backwards_reports_a_second_ask() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));

    mock.upcoming_backwards(&[4]);
    mock.upcoming_backwards(&[4]);
}

#[test]
#[should_panic(expected = "the stream should hold every needle")]
fn test_upcoming_backwards_reports_a_stream_too_short() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));

    mock.upcoming_backwards(&[4, 5]);
}

#[test]
fn test_upcoming_backwards_returns_the_next_pieces_backwards() -> Result<(), EntropyError> {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let mut first = [0u8; 2];

    mock.fill_bytes(&mut first)?;

    let needles = mock.upcoming_backwards(&[3, 1]);

    assert_eq!(needles, [vec![0x55, 0x44, 0x33], vec![0x66]]);

    let mut second = [0u8; 3];
    let mut third = [0u8; 1];

    mock.fill_bytes(&mut second)?;
    mock.fill_bytes(&mut third)?;

    assert_eq!(second, [0x33, 0x44, 0x55]);
    assert_eq!(third, [0x66]);

    Ok(())
}

// ============================================================================
// yield_over
// ============================================================================

#[test]
#[should_panic(expected = "draw 0 asked for 2 bytes")]
fn test_yield_over_reports_a_draw_of_another_size_than_asked() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let mut dest = [0u8; 2];

    mock.upcoming_backwards(&[3]);

    let _ = mock.fill_bytes(&mut dest);
}

#[test]
#[should_panic(expected = "draw 1 asked for 2 bytes")]
fn test_yield_over_reports_a_draw_past_the_ones_asked() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let mut first = [0u8; 3];
    let mut extra = [0u8; 2];

    mock.upcoming_backwards(&[3]);

    let _ = mock.fill_bytes(&mut first);
    let _ = mock.fill_bytes(&mut extra);
}

#[test]
fn test_yield_over_reports_a_stream_too_short() -> Result<(), EntropyError> {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let mut first = [0u8; 6];
    let mut refused = [0u8; 3];
    let mut last = [0u8; 2];

    mock.fill_bytes(&mut first)?;

    let result = mock.fill_bytes(&mut refused);

    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
    assert_eq!(refused, [0u8; 3]);

    mock.fill_bytes(&mut last)?;

    assert_eq!(last, [0x77, 0x88]);

    Ok(())
}

#[test]
fn test_yield_over_starts_over_for_each_mock() -> Result<(), EntropyError> {
    let one = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let other = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let mut from_one = [0u8; 4];
    let mut from_other = [0u8; 4];

    one.fill_bytes(&mut from_one)?;
    other.fill_bytes(&mut from_other)?;

    assert_eq!(from_one, [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(from_other, [0x11, 0x22, 0x33, 0x44]);

    Ok(())
}

#[test]
fn test_yield_over_hands_out_the_stream_in_order() -> Result<(), EntropyError> {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let mut first = [0u8; 3];
    let mut second = [0u8; 5];

    mock.fill_bytes(&mut first)?;
    mock.fill_bytes(&mut second)?;

    assert_eq!(first, [0x11, 0x22, 0x33]);
    assert_eq!(second, [0x44, 0x55, 0x66, 0x77, 0x88]);

    Ok(())
}

// ============================================================================
// change_behaviour
// ============================================================================

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

// ============================================================================
// call_count
// ============================================================================

#[test]
fn test_mock_entropy_source_call_count() -> Result<(), EntropyError> {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::None);
    let mut buf = [0u8; 32];

    assert_eq!(mock.call_count(), 0);

    mock.fill_bytes(&mut buf)?;
    assert_eq!(mock.call_count(), 1);

    mock.fill_bytes(&mut buf)?;
    assert_eq!(mock.call_count(), 2);

    mock.reset_count();
    assert_eq!(mock.call_count(), 0);

    Ok(())
}

// ============================================================================
// fill_bytes
// ============================================================================

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

// ============================================================================
// drop
// ============================================================================

#[test]
#[should_panic(expected = "the test failed on its own")]
fn test_drop_leaves_a_panic_already_unwinding_to_say_what_failed() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));

    mock.upcoming_backwards(&[3, 1]);

    panic!("the test failed on its own");
}

#[test]
#[should_panic(expected = "not every one of them was drawn")]
fn test_drop_reports_needles_never_drawn() {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));

    mock.upcoming_backwards(&[3, 1]);
}
