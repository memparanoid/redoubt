// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::cell::Cell;

use memutil::fill_bytes_with_pattern;
use memzer::{FastZeroizable, ZeroizationProbe};

use crate::error::BufferError;
use crate::portable::PortableBuffer;
use crate::traits::Buffer;

// create

#[test]
fn test_portable_buffer_happypath() {
    let mut portable_buffer = PortableBuffer::create(10);

    // Fill with pattern
    {
        let callback_executed = Cell::new(false);
        portable_buffer
            .open_mut(&mut |bytes| {
                callback_executed.set(true);
                fill_bytes_with_pattern(bytes, 0);
                Ok(())
            })
            .expect("Failed to open_mut(..)");
        assert!(callback_executed.get());
    }

    // Zero initialized
    {
        let callback_executed = Cell::new(false);
        portable_buffer
            .open_mut(&mut |bytes| {
                callback_executed.set(true);
                assert!(bytes.is_zeroized());
                Ok(())
            })
            .expect("Failed to open_mut(..)");
        assert!(callback_executed.get());
    }

    // Fill with pattern
    {
        let callback_executed = Cell::new(false);
        portable_buffer
            .open_mut(&mut |bytes| {
                callback_executed.set(true);
                fill_bytes_with_pattern(bytes, 1);
                Ok(())
            })
            .expect("Failed to open_mut(..)");
        assert!(callback_executed.get());
    }

    // Not zeroized
    {
        let callback_executed = Cell::new(false);
        portable_buffer
            .open_mut(&mut |bytes| {
                callback_executed.set(true);
                assert!(!bytes.is_zeroized());
                Ok(())
            })
            .expect("Failed to open_mut(..)");
        assert!(callback_executed.get());
    }

    // Zeroize
    {
        let callback_executed = Cell::new(false);
        portable_buffer
            .open_mut(&mut |bytes| {
                callback_executed.set(true);
                bytes.fast_zeroize();
                Ok(())
            })
            .expect("Failed to open_mut(..)");
        assert!(callback_executed.get());
    }

    // Assert zeroization!
    {
        let callback_executed = Cell::new(false);
        portable_buffer
            .open_mut(&mut |bytes| {
                callback_executed.set(true);
                assert!(bytes.is_zeroized());
                Ok(())
            })
            .expect("Failed to open_mut(..)");
        assert!(callback_executed.get());
    }
}

// open

#[test]
fn test_portable_buffer_open_happypath() {
    let mut portable_buffer = PortableBuffer::create(10);

    portable_buffer
        .open_mut(&mut |bytes| {
            fill_bytes_with_pattern(bytes, 0);
            Ok(())
        })
        .expect("Failed to open_mut(..)");

    portable_buffer
        .open(&mut |bytes| {
            assert!(bytes.is_zeroized());
            Ok(())
        })
        .expect("Failed to open(..)");
}

#[test]
fn test_portable_buffer_open_propagates_callback_error() {
    #[derive(Debug)]
    struct TestCallbackError {
        _code: u32,
    }

    let portable_buffer = PortableBuffer::create(10);

    let result = portable_buffer
        .open(&mut |_bytes| Err(BufferError::callback_error(TestCallbackError { _code: 42 })));

    match result {
        Err(BufferError::CallbackError(inner)) => {
            let expected_inner = TestCallbackError { _code: 42 };
            let debug_str = format!("{:?}", inner);
            let expected_debug_str = format!("{:?}", expected_inner);

            assert_eq!(debug_str, expected_debug_str);
        }
        Err(other) => panic!("expected CallbackError, got {:?}", other),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

// open_mut

#[test]
fn test_portable_buffer_open_mut_propagates_callback_error() {
    #[derive(Debug)]
    struct TestCallbackError {
        _code: u32,
    }

    let mut portable_buffer = PortableBuffer::create(10);

    let result = portable_buffer
        .open_mut(&mut |_bytes| Err(BufferError::callback_error(TestCallbackError { _code: 42 })));

    match result {
        Err(BufferError::CallbackError(inner)) => {
            let expected_inner = TestCallbackError { _code: 42 };
            let debug_str = format!("{:?}", inner);
            let expected_debug_str = format!("{:?}", expected_inner);

            assert_eq!(debug_str, expected_debug_str);
        }
        Err(other) => panic!("expected CallbackError, got {:?}", other),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

// len

#[test]
fn test_portable_buffer_len() {
    let portable_buffer = PortableBuffer::create(10);
    assert_eq!(portable_buffer.len(), 10);
}

// is_empty

#[test]
fn test_portable_buffer_is_empty_false() {
    let portable_buffer = PortableBuffer::create(10);
    assert!(!portable_buffer.is_empty());
}

#[test]
fn test_portable_buffer_is_empty_true() {
    let portable_buffer = PortableBuffer::create(0);
    assert!(portable_buffer.is_empty());
}
