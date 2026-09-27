// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::{AssertZeroizeOnDrop, FastZeroizable, ZeroizationProbe};

use crate::error::BufferError;
use crate::portable_buffer::PortableBuffer;
use crate::traits::Buffer;

#[derive(Debug, thiserror::Error)]
#[error("a test callback refused with code {code}")]
struct TestCallbackError {
    code: u32,
}

// ============================================================================
// PortableBuffer
// ============================================================================

#[test]
fn test_fast_zeroize_empties_the_buffer() {
    let mut portable_buffer = PortableBuffer::create(10);

    portable_buffer.unzeroize();
    assert!(!portable_buffer.is_zeroized());

    portable_buffer.fast_zeroize();
    assert!(portable_buffer.is_zeroized());
}

#[test]
fn test_drop_zeroizes_the_buffer() {
    let mut portable_buffer = PortableBuffer::create(10);

    portable_buffer.unzeroize();
    assert!(!portable_buffer.is_zeroized());

    portable_buffer.assert_zeroize_on_drop();
}

// ============================================================================
// create
// ============================================================================

#[test]
fn test_create_returns_an_empty_buffer() {
    let portable_buffer = PortableBuffer::create(10);

    assert!(portable_buffer.is_zeroized());
}

// ============================================================================
// Debug
// ============================================================================

#[test]
fn test_debug_does_not_expose_contents() {
    let buffer = PortableBuffer::create(32);
    let debug_output = format!("{:?}", buffer);

    assert!(debug_output.contains("PortableBuffer"));
    assert!(debug_output.contains("len"));
    assert!(debug_output.contains("32"));

    assert!(!debug_output.contains("inner"));
    assert!(!debug_output.contains("Vec"));
}

// ============================================================================
// open
// ============================================================================

#[test]
fn test_open_propagates_callback_error() {
    let mut portable_buffer = PortableBuffer::create(10);

    let result = portable_buffer
        .open(&mut |_bytes| Err(BufferError::callback_error(TestCallbackError { code: 42 })));

    assert!(matches!(
        result,
        Err(BufferError::CallbackError(inner))
            if format!("{inner:?}") == format!("{:?}", TestCallbackError { code: 42 })
    ));
}

#[test]
fn test_open_hands_the_callback_what_the_buffer_holds() -> Result<(), BufferError> {
    let mut portable_buffer = PortableBuffer::create(10);

    portable_buffer.unzeroize();

    portable_buffer.open(&mut |bytes| {
        assert_eq!(bytes, &[1_u8; 10]);
        Ok(())
    })
}

// ============================================================================
// open_mut
// ============================================================================

#[test]
fn test_open_mut_propagates_callback_error() {
    let mut portable_buffer = PortableBuffer::create(10);

    let result = portable_buffer
        .open_mut(&mut |_bytes| Err(BufferError::callback_error(TestCallbackError { code: 42 })));

    assert!(matches!(
        result,
        Err(BufferError::CallbackError(inner))
            if format!("{inner:?}") == format!("{:?}", TestCallbackError { code: 42 })
    ));
}

#[test]
fn test_open_mut_keeps_what_the_callback_wrote() -> Result<(), BufferError> {
    let mut portable_buffer = PortableBuffer::create(10);

    portable_buffer.open_mut(&mut |bytes| {
        bytes.fill(0xAB);
        Ok(())
    })?;

    portable_buffer.open(&mut |bytes| {
        assert_eq!(bytes, &[0xAB_u8; 10]);
        Ok(())
    })
}

// ============================================================================
// len
// ============================================================================

#[test]
fn test_len_returns_the_length_it_was_created_with() {
    let portable_buffer = PortableBuffer::create(10);

    assert_eq!(portable_buffer.len(), 10);
}

// ============================================================================
// is_empty
// ============================================================================

#[test]
fn test_is_empty_returns_false_when_it_holds_bytes() {
    let portable_buffer = PortableBuffer::create(10);

    assert!(!portable_buffer.is_empty());
}

#[test]
fn test_is_empty_returns_true_when_it_holds_none() {
    let portable_buffer = PortableBuffer::create(0);

    assert!(portable_buffer.is_empty());
}
