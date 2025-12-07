// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod buffer;
mod storage;

use membuffer::BufferError;

use crate::master_key::consts::MASTER_KEY_LEN;
use crate::master_key::open;

#[test]
fn test_open_propagates_error() {
    #[derive(Debug)]
    struct CustomCallbackError {}

    let result = open(&mut |_| Err(BufferError::callback_error(CustomCallbackError {})));
    assert!(result.is_err());
}

#[test]
fn test_open_propagates_ok() {
    let mut callback_executed = false;

    open(&mut |bytes| {
        callback_executed = true;
        assert_eq!(bytes.len(), MASTER_KEY_LEN);
        Ok(())
    })
    .expect("Failed to open(..)");

    assert!(callback_executed);
}
