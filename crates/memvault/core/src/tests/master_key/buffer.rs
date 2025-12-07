// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::ZeroizationProbe;

use crate::master_key::buffer::{create_buffer, create_initialized_buffer};
use crate::master_key::consts::MASTER_KEY_LEN;
#[cfg(target_os = "linux")]
use crate::tests::utils::{block_mem_syscalls, run_test_as_subprocess};

#[test]
fn test_create_buffer_returns_correct_length() {
    let buffer = create_buffer(false);
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
fn test_create_buffer_guarded_returns_correct_length() {
    let buffer = create_buffer(true);
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
    let buffer = create_initialized_buffer();
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
    block_mem_syscalls();

    // @TODO: Add debug or `name` method to the buffer to assert it's actually a PortableBuffer
    let buffer = create_buffer(false);
    buffer
        .open(&mut |bytes| {
            assert_eq!(bytes.len(), MASTER_KEY_LEN);
            Ok(())
        })
        .expect("Failed to open buffer");
}
