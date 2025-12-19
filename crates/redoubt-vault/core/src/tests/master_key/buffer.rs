// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::ZeroizationProbe;

use crate::master_key::buffer::{create_buffer, create_initialized_buffer};
use crate::master_key::consts::MASTER_KEY_LEN;
#[cfg(target_os = "linux")]
use crate::tests::utils::{
    block_getrandom, block_madvise, block_mlock, block_mprotect, block_munlock, block_openat,
    block_read, run_test_as_subprocess,
};

#[test]
fn test_create_buffer_returns_correct_length() {
    let mut buffer = create_buffer();

    #[cfg(all(unix, not(target_os = "wasi")))]
    {
        let debug_output = format!("{:?}", buffer);
        assert!(
            debug_output.contains("PageBuffer"),
            "Expected PageBuffer (not fallback)"
        );
        assert!(
            debug_output.contains("MemProtected"),
            "Expected MemProtected strategy when not guarded"
        );
    }

    #[cfg(any(target_os = "wasi", not(unix)))]
    {
        let debug_output = format!("{:?}", buffer);
        assert!(
            debug_output.contains("PortableBuffer"),
            "Expected PortableBuffer on non-unix platforms"
        );
    }

    buffer
        .open(&mut |bytes| {
            assert!(
                bytes.is_zeroized(),
                "Key is not initialized: should be zeroized"
            );
            Ok(())
        })
        .expect("Failed to open buffer");
}

#[test]
fn test_create_initialized_buffer_returns_correct_length() {
    let mut buffer = create_initialized_buffer();
    buffer
        .open(&mut |bytes| {
            assert_eq!(bytes.len(), MASTER_KEY_LEN);
            Ok(())
        })
        .expect("Failed to open buffer");
}

#[cfg(target_os = "linux")]
#[test]
fn test_create_buffer_falls_back_to_portable_on_protected_failure() {
    let exit_code = run_test_as_subprocess(
        "tests::master_key::buffer::subprocess_create_buffer_falls_back_to_portable",
    );
    assert_eq!(exit_code, Some(0), "subprocess test failed");
}

// ==============================
// ===== Subprocess tests =======
// ==============================

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn subprocess_create_buffer_falls_back_to_portable() {
    block_mprotect();
    block_mlock();
    block_munlock();
    block_madvise();

    let mut buffer = create_buffer();

    // Assert that we fell back to PortableBuffer when syscalls are blocked
    assert!(
        format!("{:?}", buffer).contains("PortableBuffer"),
        "Expected PortableBuffer fallback when mem syscalls are blocked"
    );

    buffer
        .open(&mut |bytes| {
            assert_eq!(bytes.len(), MASTER_KEY_LEN);
            Ok(())
        })
        .expect("Failed to open buffer");
}

#[cfg(target_os = "linux")]
#[test]
fn test_create_initialized_buffer_panics_on_entropy_failure() {
    let exit_code = run_test_as_subprocess(
        "tests::master_key::buffer::subprocess_create_initialized_buffer_panics_on_entropy_failure",
    );
    // Rust panic exits with code 101
    assert_eq!(exit_code, Some(101), "subprocess should have panicked");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn subprocess_create_initialized_buffer_panics_on_entropy_failure() {
    block_getrandom();
    block_read();
    block_openat();

    // This should panic with "CRITICAL: Entropy not available"
    let _ = create_initialized_buffer();
}
