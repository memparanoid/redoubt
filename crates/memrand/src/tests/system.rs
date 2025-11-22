// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use getrandom::Error as GetRandomError;

use crate::error::EntropyError;
use crate::system::SystemEntropySource;
use crate::traits::EntropySource;

#[test]
fn test_fill_bytes_with_failure() {
    let mut bytes = [0u8; 32];
    let result =
        SystemEntropySource::fill_bytes_with(&|_| Err(GetRandomError::UNSUPPORTED), &mut bytes);

    assert!(result.is_err());
    assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)))
}

#[test]
fn test_fill_bytes_ok() {
    let source = SystemEntropySource {};
    let mut bytes = [0u8; 32];
    let result = source.fill_bytes(&mut bytes);

    assert!(result.is_ok());
}
