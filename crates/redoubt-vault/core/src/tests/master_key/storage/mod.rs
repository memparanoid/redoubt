// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod portable;
mod std;

// From the root: the `std` above is a module of this crate, and it shadows the
// one this name would otherwise reach.
use ::std::error::Error;

use crate::master_key::{consts::MASTER_KEY_LEN, leak_master_key};

#[test]
fn test_leak_master_key_ok() -> Result<(), Box<dyn Error>> {
    let key = leak_master_key(16)?;
    assert_eq!(key.len(), 16);

    Ok(())
}

#[test]
fn test_leak_master_key_propagates_storage_error() {
    let result = leak_master_key(MASTER_KEY_LEN + 1);
    assert!(result.is_err());
}
