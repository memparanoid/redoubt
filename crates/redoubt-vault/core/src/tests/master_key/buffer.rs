// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_buffer::BufferError;
use redoubt_rand::test_utils::{MockEntropySource, MockEntropySourceBehaviour};
use redoubt_zero::ZeroizationProbe;

#[cfg(target_os = "linux")]
use redoubt_test_utils::{block_syscall, is_seccomp_available, run_test_as_subprocess};

use crate::master_key::buffer::{create_buffer, create_initialized_buffer, initialize_buffer_with};
use crate::master_key::consts::MASTER_KEY_LEN;

const KEY: [u8; MASTER_KEY_LEN] = [
    0x4e, 0x91, 0x2b, 0xd7, 0x63, 0xa8, 0x15, 0xfc, 0x39, 0xc6, 0x70, 0x0d, 0xb4, 0x5a, 0xe2, 0x87,
    0x1c, 0xf3, 0x96, 0x2f, 0xd8, 0x41, 0x7b, 0xa5, 0x08, 0xec, 0x53, 0xbe, 0x24, 0x9a, 0x6f, 0xc1,
];

// ============================================================================
// create_buffer
// ============================================================================

#[cfg(target_os = "linux")]
#[test]
fn test_create_buffer_propagates_page_error() {
    if !is_seccomp_available() {
        eprintln!("Skipping: seccomp not available (QEMU/unsupported platform)");
        return;
    }

    let exit_code =
        run_test_as_subprocess("tests::master_key::buffer::subprocess_create_buffer_page_error");

    assert_eq!(exit_code, Some(0), "subprocess test failed");
}

#[test]
fn test_create_buffer_returns_an_empty_key_of_the_whole_length()
-> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = create_buffer()?;

    #[cfg(unix)]
    assert!(format!("{buffer:?}").contains("PageBuffer"));

    #[cfg(not(unix))]
    assert!(format!("{buffer:?}").contains("PortableBuffer"));

    buffer.open(&mut |bytes| {
        assert_eq!(bytes.len(), MASTER_KEY_LEN);
        assert!(bytes.is_zeroized(), "a key nothing has filled is not empty");

        Ok(())
    })?;

    Ok(())
}

// ============================================================================
// create_initialized_buffer
// ============================================================================

#[cfg(target_os = "linux")]
#[test]
fn test_create_initialized_buffer_propagates_create_buffer_error() {
    if !is_seccomp_available() {
        eprintln!("Skipping: seccomp not available (QEMU/unsupported platform)");
        return;
    }

    let exit_code = run_test_as_subprocess(
        "tests::master_key::buffer::subprocess_create_initialized_buffer_page_error",
    );

    assert_eq!(exit_code, Some(0), "subprocess test failed");
}

#[cfg(target_os = "linux")]
#[test]
fn test_create_initialized_buffer_propagates_initialize_buffer_with_error() {
    let exit_code = run_test_as_subprocess(
        "tests::master_key::buffer::subprocess_create_initialized_buffer_initialize_error",
    );

    assert_eq!(exit_code, Some(0), "subprocess test failed");
}

#[test]
fn test_create_initialized_buffer_returns_a_filled_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = create_initialized_buffer()?;

    buffer.open(&mut |bytes| {
        assert_eq!(bytes.len(), MASTER_KEY_LEN);
        assert!(!bytes.is_zeroized(), "the key was never filled");

        Ok(())
    })?;

    Ok(())
}

// ============================================================================
// initialize_buffer_with
// ============================================================================

#[test]
fn test_initialize_buffer_with_propagates_entropy_error() -> Result<(), Box<dyn std::error::Error>> {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::FailAlways);
    let mut buffer = create_buffer()?;

    let result = initialize_buffer_with(&entropy, &mut *buffer);

    assert!(matches!(result, Err(BufferError::CallbackError(_))));

    Ok(())
}

#[test]
fn test_initialize_buffer_with_fills_the_key_from_the_source() -> Result<(), Box<dyn std::error::Error>> {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&KEY));
    let mut buffer = create_buffer()?;

    initialize_buffer_with(&entropy, &mut *buffer)?;

    buffer.open(&mut |bytes| {
        assert_eq!(bytes, KEY);

        Ok(())
    })?;

    Ok(())
}

// ==============================
// ===== Subprocess tests =======
// ==============================

#[cfg(target_os = "linux")]
fn block_the_page() -> Result<(), Box<dyn std::error::Error>> {
    block_syscall("mprotect")?;
    block_syscall("mlock")?;
    block_syscall("munlock")?;
    block_syscall("madvise")?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn subprocess_create_buffer_page_error() -> Result<(), Box<dyn std::error::Error>> {
    block_the_page()?;

    assert!(matches!(create_buffer(), Err(BufferError::Page(_))));

    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn subprocess_create_initialized_buffer_page_error() -> Result<(), Box<dyn std::error::Error>> {
    block_the_page()?;

    assert!(matches!(
        create_initialized_buffer(),
        Err(BufferError::Page(_))
    ));

    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn subprocess_create_initialized_buffer_initialize_error() -> Result<(), Box<dyn std::error::Error>> {
    block_syscall("getrandom")?;
    block_syscall("read")?;
    block_syscall("openat")?;

    assert!(matches!(
        create_initialized_buffer(),
        Err(BufferError::CallbackError(_))
    ));

    Ok(())
}
