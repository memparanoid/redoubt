// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod buffer;
mod storage;

use core::sync::atomic::Ordering;
use std::error::Error;

use redoubt_buffer::BufferError;
use redoubt_hkdf::hkdf;

use crate::master_key::consts::{CIPHERBOX_KEY_INFO_LEN, MASTER_KEY_LEN};
use crate::master_key::{
    cipherbox_key_info, derive_cipherbox_key, derive_next_cipherbox_key, leak_master_key,
};
use crate::utils::CIPHERBOX_UID;

const INFO: [u8; CIPHERBOX_KEY_INFO_LEN] =
    *b"redoubt.cipherbox.v1\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const OTHER_INFO: [u8; CIPHERBOX_KEY_INFO_LEN] =
    *b"redoubt.cipherbox.v1\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00";

// ============================================================================
// cipherbox_key_info
// ============================================================================

#[test]
fn test_cipherbox_key_info_returns_the_prefix_the_pid_and_the_uid() {
    assert_eq!(
        cipherbox_key_info(0x0403_0201, 0x0C0B_0A09_0807_0605),
        *b"redoubt.cipherbox.v1\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
    );
}

#[test]
fn test_cipherbox_key_info_returns_another_info_for_another_pid() {
    assert_ne!(cipherbox_key_info(1, 0), cipherbox_key_info(2, 0));
}

#[test]
fn test_cipherbox_key_info_returns_another_info_for_another_uid() {
    assert_ne!(cipherbox_key_info(1, 0), cipherbox_key_info(1, 1));
}

// ============================================================================
// derive_cipherbox_key
// ============================================================================

#[test]
fn test_derive_cipherbox_key_propagates_storage_error() {
    let result = derive_cipherbox_key(MASTER_KEY_LEN + 1, &INFO);

    assert!(matches!(result, Err(BufferError::CallbackError(_))));
}

#[test]
fn test_derive_cipherbox_key_returns_a_key_of_the_size_asked_for() -> Result<(), Box<dyn Error>> {
    let key = derive_cipherbox_key(16, &INFO)?;

    assert_eq!(key.len(), 16);

    Ok(())
}

#[test]
fn test_derive_cipherbox_key_returns_the_hkdf_of_the_master_key_under_the_info()
-> Result<(), Box<dyn Error>> {
    let master_key = leak_master_key(MASTER_KEY_LEN)?;
    let mut expected = [0_u8; MASTER_KEY_LEN];

    hkdf(&[], &master_key, &INFO, &mut expected)?;

    let key = derive_cipherbox_key(MASTER_KEY_LEN, &INFO)?;

    assert_eq!(key.as_slice(), expected.as_slice());

    Ok(())
}

#[test]
fn test_derive_cipherbox_key_returns_a_key_that_is_not_the_master_key() -> Result<(), Box<dyn Error>>
{
    let master_key = leak_master_key(MASTER_KEY_LEN)?;
    let key = derive_cipherbox_key(MASTER_KEY_LEN, &INFO)?;

    assert_ne!(key.as_slice(), master_key.as_slice());

    Ok(())
}

#[test]
fn test_derive_cipherbox_key_returns_the_same_key_for_the_same_info() -> Result<(), Box<dyn Error>>
{
    let first = derive_cipherbox_key(MASTER_KEY_LEN, &INFO)?;
    let second = derive_cipherbox_key(MASTER_KEY_LEN, &INFO)?;

    assert_eq!(first.as_slice(), second.as_slice());

    Ok(())
}

#[test]
fn test_derive_cipherbox_key_returns_another_key_for_another_info() -> Result<(), Box<dyn Error>> {
    let one = derive_cipherbox_key(MASTER_KEY_LEN, &INFO)?;
    let other = derive_cipherbox_key(MASTER_KEY_LEN, &OTHER_INFO)?;

    assert_ne!(one.as_slice(), other.as_slice());

    Ok(())
}

// ============================================================================
// derive_next_cipherbox_key
// ============================================================================

#[test]
fn test_derive_next_cipherbox_key_returns_the_key_under_this_process_and_the_next_uid()
-> Result<(), Box<dyn Error>> {
    let info = cipherbox_key_info(std::process::id(), CIPHERBOX_UID.load(Ordering::Relaxed));
    let expected = derive_cipherbox_key(MASTER_KEY_LEN, &info)?;

    let key = derive_next_cipherbox_key(MASTER_KEY_LEN)?;

    assert_eq!(key.as_slice(), expected.as_slice());

    Ok(())
}

#[test]
fn test_derive_next_cipherbox_key_returns_another_key_once_a_uid_is_taken()
-> Result<(), Box<dyn Error>> {
    let before = derive_next_cipherbox_key(MASTER_KEY_LEN)?;

    CIPHERBOX_UID.fetch_add(1, Ordering::Relaxed);

    let after = derive_next_cipherbox_key(MASTER_KEY_LEN)?;

    assert_ne!(before.as_slice(), after.as_slice());

    Ok(())
}

// ============================================================================
// leak_master_key
// ============================================================================

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
