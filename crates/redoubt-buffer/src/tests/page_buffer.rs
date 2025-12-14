// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for PageBuffer.

use serial_test::serial;

use redoubt_zero::ZeroizationProbe;

use crate::page_buffer::{PageBuffer, ProtectionStrategy};
use crate::traits::Buffer;

// =============================================================================
// new()
// =============================================================================

#[test]
#[serial(page_buffer)]
fn test_new_mem_protected() {
    let buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");
    let debug_output = format!("{:?}", buffer);
    assert!(debug_output.contains("MemProtected"));
}

#[test]
#[serial(page_buffer)]
fn test_new_mem_non_protected() {
    let buffer =
        PageBuffer::new(ProtectionStrategy::MemNonProtected, 32).expect("Failed to new(..)");
    let debug_output = format!("{:?}", buffer);
    assert!(debug_output.contains("MemNonProtected"));
}

#[test]
#[serial(page_buffer)]
fn test_new_returns_creation_failed() {
    use crate::error::PageError;

    let mut original = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) };

    let tiny = libc::rlimit {
        rlim_cur: 0,
        rlim_max: original.rlim_max,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_AS, &tiny) };

    let result = PageBuffer::new(ProtectionStrategy::MemProtected, 32);

    assert!(result.is_err());
    assert!(matches!(result, Err(PageError::Create)));

    unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) };
}

#[cfg(target_os = "linux")]
mod seccomp_new {
    use super::*;
    use crate::error::PageError;
    use crate::tests::utils::{block_mlock, block_mprotect, run_test_as_subprocess};

    #[test]
    #[ignore]
    fn subprocess_test_new_returns_lock_failed() {
        block_mlock();
        let result = PageBuffer::new(ProtectionStrategy::MemProtected, 32);

        assert!(result.is_err());
        assert!(matches!(result, Err(PageError::Lock)));
    }

    #[test]
    #[serial(page_buffer)]
    fn test_new_returns_lock_failed() {
        let exit_code = run_test_as_subprocess(
            "tests::page_buffer::seccomp_new::subprocess_test_new_returns_lock_failed",
        );
        assert_eq!(
            exit_code,
            Some(0),
            "Subprocess should exit cleanly after assertion"
        );
    }

    #[test]
    #[ignore]
    fn subprocess_test_new_returns_protection_failed() {
        block_mprotect();
        let result = PageBuffer::new(ProtectionStrategy::MemProtected, 32);

        assert!(result.is_err());
        assert!(matches!(result, Err(PageError::Protect)));
    }

    #[test]
    #[serial(page_buffer)]
    fn test_new_returns_protection_failed() {
        let exit_code = run_test_as_subprocess(
            "tests::page_buffer::seccomp_new::subprocess_test_new_returns_protection_failed",
        );
        assert_eq!(
            exit_code,
            Some(0),
            "Subprocess should exit cleanly after assertion"
        );
    }
}

// =============================================================================
// open()
// =============================================================================

#[test]
#[serial(page_buffer)]
fn test_open_reads_data() {
    let mut buffer =
        PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

    buffer
        .open_mut(&mut |bytes| {
            bytes[0] = 0xAB;
            Ok(())
        })
        .expect("Failed to open_mut(..)");

    buffer
        .open(&mut |bytes| {
            assert_eq!(bytes[0], 0xAB);
            Ok(())
        })
        .expect("Failed to open(..)");
}

#[test]
#[serial(page_buffer)]
fn test_open_mem_non_protected() {
    let mut buffer =
        PageBuffer::new(ProtectionStrategy::MemNonProtected, 32).expect("Failed to new(..)");

    buffer
        .open_mut(&mut |bytes| {
            bytes[0] = 0xCD;
            Ok(())
        })
        .expect("Failed to open_mut(..)");

    buffer
        .open(&mut |bytes| {
            assert_eq!(bytes[0], 0xCD);
            Ok(())
        })
        .expect("Failed to open(..)");
}

#[test]
#[serial(page_buffer)]
fn test_open_propagates_callback_error() {
    use crate::error::BufferError;

    let mut buffer =
        PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

    let result = buffer.open(&mut |_| Err(BufferError::callback_error("test error")));

    assert!(result.is_err());
    assert!(matches!(result, Err(BufferError::CallbackError(_))));
}

#[cfg(target_os = "linux")]
mod seccomp_open {
    use super::*;
    use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

    #[test]
    #[ignore]
    fn subprocess_test_open_aborts_on_unprotect_failure() {
        let mut buffer =
            PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

        block_mprotect();
        let _ = buffer.open(&mut |_bytes| Ok(()));
    }

    #[test]
    #[serial(page_buffer)]
    fn test_open_aborts_on_unprotect_failure() {
        let exit_code = run_test_as_subprocess(
            "tests::page_buffer::seccomp_open::subprocess_test_open_aborts_on_unprotect_failure",
        );
        assert_eq!(exit_code, Some(3), "Expected UnprotectionFailed abort");
    }

    #[test]
    #[ignore]
    fn subprocess_test_open_aborts_on_protect_failure() {
        let mut buffer =
            PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

        let _ = buffer.open(&mut |_bytes| {
            block_mprotect();
            Ok(())
        });
    }

    #[test]
    #[serial(page_buffer)]
    fn test_open_aborts_on_protect_failure() {
        let exit_code = run_test_as_subprocess(
            "tests::page_buffer::seccomp_open::subprocess_test_open_aborts_on_protect_failure",
        );
        assert_eq!(exit_code, Some(2), "Expected ProtectionFailed abort");
    }
}

// =============================================================================
// open_mut()
// =============================================================================

#[test]
#[serial(page_buffer)]
fn test_open_mut_writes_data() {
    let mut buffer =
        PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

    buffer
        .open_mut(&mut |bytes| {
            bytes.fill(0xFF);
            Ok(())
        })
        .expect("Failed to open_mut(..)");

    buffer
        .open(&mut |bytes| {
            assert!(bytes.iter().all(|&b| b == 0xFF));
            Ok(())
        })
        .expect("Failed to open(..)");
}

#[test]
#[serial(page_buffer)]
fn test_open_mut_zeroize() {
    let mut buffer =
        PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

    buffer
        .open_mut(&mut |bytes| {
            bytes.fill(0xFF);
            Ok(())
        })
        .expect("Failed to open_mut(..)");

    buffer
        .open_mut(&mut |bytes| {
            bytes.fill(0);
            Ok(())
        })
        .expect("Failed to open_mut(..)");

    buffer
        .open(&mut |bytes| {
            assert!(bytes.is_zeroized());
            Ok(())
        })
        .expect("Failed to open(..)");
}

#[test]
#[serial(page_buffer)]
fn test_open_mut_propagates_callback_error() {
    use crate::error::BufferError;

    let mut buffer =
        PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

    let result = buffer.open_mut(&mut |_| Err(BufferError::callback_error("test error")));

    assert!(result.is_err());
    assert!(matches!(result, Err(BufferError::CallbackError(_))));
}

#[cfg(target_os = "linux")]
mod seccomp_open_mut {
    use super::*;
    use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

    #[test]
    #[ignore]
    fn subprocess_test_open_mut_aborts_on_unprotect_failure() {
        let mut buffer =
            PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

        block_mprotect();
        let _ = buffer.open_mut(&mut |_bytes| Ok(()));
    }

    #[test]
    #[serial(page_buffer)]
    fn test_open_mut_aborts_on_unprotect_failure() {
        let exit_code = run_test_as_subprocess(
            "tests::page_buffer::seccomp_open_mut::subprocess_test_open_mut_aborts_on_unprotect_failure",
        );
        assert_eq!(exit_code, Some(3), "Expected UnprotectionFailed abort");
    }

    #[test]
    #[ignore]
    fn subprocess_test_open_mut_aborts_on_protect_failure() {
        let mut buffer =
            PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

        let _ = buffer.open_mut(&mut |_bytes| {
            block_mprotect();
            Ok(())
        });
    }

    #[test]
    #[serial(page_buffer)]
    fn test_open_mut_aborts_on_protect_failure() {
        let exit_code = run_test_as_subprocess(
            "tests::page_buffer::seccomp_open_mut::subprocess_test_open_mut_aborts_on_protect_failure",
        );
        assert_eq!(exit_code, Some(2), "Expected ProtectionFailed abort");
    }
}

// =============================================================================
// len() / is_empty()
// =============================================================================

#[test]
#[serial(page_buffer)]
fn test_len() {
    let buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 64).expect("Failed to new(..)");
    assert_eq!(buffer.len(), 64);
}

#[test]
#[serial(page_buffer)]
fn test_is_empty_false() {
    let buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");
    assert!(!buffer.is_empty());
}

#[test]
#[serial(page_buffer)]
fn test_is_empty_true() {
    let buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 0).expect("Failed to new(..)");
    assert!(buffer.is_empty());
}

// =============================================================================
// dispose()
// =============================================================================

#[test]
#[serial(page_buffer)]
fn test_dispose() {
    let mut buffer =
        PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");

    buffer
        .open_mut(&mut |bytes| {
            bytes.fill(0xFF);
            Ok(())
        })
        .expect("Failed to open_mut(..)");

    buffer.dispose();
}

// =============================================================================
// Debug
// =============================================================================

#[test]
#[serial(page_buffer)]
fn test_page_buffer_debug_does_not_expose_contents() {
    let buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 32).expect("Failed to new(..)");
    let debug_output = format!("{:?}", buffer);

    // Should contain struct name, length, and strategy
    assert!(debug_output.contains("PageBuffer"));
    assert!(debug_output.contains("len"));
    assert!(debug_output.contains("32"));
    assert!(debug_output.contains("strategy"));
    assert!(debug_output.contains("MemProtected"));
}

// =============================================================================
// acquire() / release() - spinlock contention
// =============================================================================
