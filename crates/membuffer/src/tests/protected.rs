// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::cell::Cell;

use serial_test::serial;

use memzer::{FastZeroizable, ZeroizationProbe};

use crate::error::ProtectedBufferError;
use crate::protected::{ProtectedBuffer, ProtectionStrategy, TryCreateStage};
use crate::traits::Buffer;
use crate::utils::fill_with_pattern;

/// Reads the amount of locked memory (in kB) for the current process.
///
/// Parses `/proc/self/status` and extracts the `VmLck` field, which represents
/// memory that has been locked into RAM via mlock() and cannot be swapped out.
///
/// # Returns
///
/// The amount of locked memory in kilobytes, or 0 if the field cannot be found
/// or parsed (e.g., on non-Linux systems).
///
/// # Example
///
/// ```text
/// /proc/self/status contains lines like:
///
/// Name:   my_process
/// VmPeak:   123456 kB
/// VmSize:   112233 kB
/// VmLck:         4 kB   ← this is what we extract
/// VmPin:         0 kB
/// ```
fn get_locked_memory_kb() -> usize {
    // Read the entire status file for this process
    // /proc/self is a symlink to /proc/<current_pid>
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return 0, // Non-Linux or restricted environment
    };

    for line in status.lines() {
        // VmLck: Amount of memory locked with mlock()
        // Format: "VmLck:       <number> kB"
        if line.starts_with("VmLck:") {
            // Split by whitespace:
            // "VmLck:       4 kB" → ["VmLck:", "4", "kB"]
            //                         [0]      [1]  [2]
            let parts: Vec<&str> = line.split_whitespace().collect();

            // parts[1] contains the numeric value as a string
            if parts.len() >= 2 {
                return parts[1].parse().unwrap_or(0);
            }
        }
    }

    0 // VmLck field not found
}

fn run_protected_buffer_happy_path_test(strategy: ProtectionStrategy) {
    let mut protected_buffer =
        ProtectedBuffer::try_create(strategy, 10).expect("Failed to create ProtectedBuffer");

    // Zero initialized
    {
        let callback_executed = Cell::new(false);
        protected_buffer
            .open_mut(|bytes| {
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
        protected_buffer
            .open_mut(|bytes| {
                callback_executed.set(true);
                fill_with_pattern(bytes, 1);
                Ok(())
            })
            .expect("Failed to open_mut(..)");
        assert!(callback_executed.get());
    }

    // Not zeroized
    {
        let callback_executed = Cell::new(false);
        protected_buffer
            .open_mut(|bytes| {
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
        protected_buffer
            .open_mut(|bytes| {
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
        protected_buffer
            .open_mut(|bytes| {
                callback_executed.set(true);
                assert!(bytes.is_zeroized());
                Ok(())
            })
            .expect("Failed to open_mut(..)");
        assert!(callback_executed.get());
    }
}

// try_create

#[serial(rlimit)]
#[test]
fn test_protected_buffer_mem_protected_strategy_happypath() {
    run_protected_buffer_happy_path_test(ProtectionStrategy::MemProtected);
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_mem_non_protected_strategy_happypath() {
    run_protected_buffer_happy_path_test(ProtectionStrategy::MemNonProtected);
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_reports_page_creation_failed_error() {
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

    let result = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10);
    assert!(matches!(
        result,
        Err(ProtectedBufferError::PageCreationFailed)
    ));

    unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) };
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_reports_lock_failed_error() {
    let mut original = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut original) };

    let zero_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &zero_limit) };

    let result = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10);
    assert!(matches!(result, Err(ProtectedBufferError::LockFailed)));

    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &original) };
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_reports_protection_failed_error() {
    let result =
        ProtectedBuffer::try_create_with(ProtectionStrategy::MemProtected, 10, &mut |stage, pb| {
            match stage {
                TryCreateStage::Lock => {}
                TryCreateStage::Protect => {
                    pb.munmap();
                }
                TryCreateStage::FillWithPattern0 => {
                    panic!("unreachable: try_create_with will will fail on protect")
                }
            }
        });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ProtectedBufferError::ProtectionFailed)
    ));
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_propages_fill_with_pattern_0_error() {
    let result =
        ProtectedBuffer::try_create_with(ProtectionStrategy::MemProtected, 10, &mut |stage, pb| {
            match stage {
                TryCreateStage::Lock => {}
                TryCreateStage::Protect => {}
                TryCreateStage::FillWithPattern0 => {
                    pb.munmap();
                }
            }
        });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ProtectedBufferError::UnprotectionFailed)
    ));
}

// protect & unprotect

#[serial(rlimit)]
#[test]
fn test_protected_buffer_protect_prevents_read_unprotect_allows_read() {
    let mut protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("expected ProtectedBuffer creation to succeed");

    // After try_create, buffer is protected (PROT_NONE)
    // Verify callback is called but we can't read (would SIGSEGV)
    let callback_got_executed = Cell::new(false);
    protected_buffer.with_self_ptr(&mut |ptr| {
        callback_got_executed.set(true);
        assert!(!ptr.is_null());
    });
    assert!(callback_got_executed.get());

    // Modify content to fill with u8::MAX
    protected_buffer
        .open_mut(|bytes| {
            fill_with_pattern(bytes, u8::MAX);
            Ok(())
        })
        .expect("Failed to open_mut(..)");

    // Unprotect to allow read
    protected_buffer
        .unprotect()
        .expect("expected unprotect to succeed");

    let callback_got_executed = Cell::new(false);
    protected_buffer.with_self_ptr(&mut |ptr| {
        callback_got_executed.set(true);
        let value = unsafe { core::ptr::read_volatile(ptr) };
        // First byte is u8::MAX
        assert_eq!(value, u8::MAX);
    });
    assert!(callback_got_executed.get());

    // Re-protect
    protected_buffer
        .protect()
        .expect("expected protect to succeed");

    // Reading from a PROT_NONE page triggers SIGSEGV which crashes the process.
    // We fork so the child crashes while the parent verifies the signal.
    let callback_got_executed = Cell::new(false);
    protected_buffer.with_self_ptr(&mut |ptr| {
        callback_got_executed.set(true);
        let pid = unsafe { libc::fork() };

        match pid {
            -1 => panic!("fork failed"),
            0 => {
                // Child: attempt read from protected page - should SIGSEGV
                let _ = unsafe { core::ptr::read_volatile(ptr) };
                // If we get here, protection failed, just exit with code 0
                unsafe { libc::_exit(0) };
            }
            child_pid => {
                // Parent: wait for child and verify it was killed by signal
                let mut status: libc::c_int = 0;
                unsafe { libc::waitpid(child_pid, &mut status, 0) };

                // Assert that child exited with SIGSEGV
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGSEGV);
            }
        }
    });
    assert!(callback_got_executed.get());
}

// lock

#[serial(rlimit)]
#[test]
fn test_protected_buffer_lock_increases_vmlck() {
    // Baseline: how much memory is currently locked?
    let before = get_locked_memory_kb();

    let protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemNonProtected, 4096)
        .expect("Failed to create ProtectedBuffer");

    let after = get_locked_memory_kb();

    assert!(
        after > before,
        "VmLck should increase after mlock: before={} after={}",
        before,
        after
    );

    drop(protected_buffer);

    let after_drop = get_locked_memory_kb();

    assert_eq!(
        before, after_drop,
        "VmLck should return to baseline after munlock: expected={} actual={}",
        before, after_drop
    );
}

// open

#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_propagates_unprotect_error() {
    let mut buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("expected ProtectedBuffer creation to succeed");

    buffer.munmap();

    let result = buffer.open(|_| Ok(()));

    assert!(matches!(
        result,
        Err(ProtectedBufferError::UnprotectionFailed)
    ));
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_fails_if_not_available() {
    let mut protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("Failed to create ProtectedBuffer");
    protected_buffer.fast_zeroize();

    let result = protected_buffer.open(|_| Ok(()));

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ProtectedBufferError::PageNoLongerAvailable)
    ));
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_propagates_callback_error() {
    #[derive(Debug)]
    struct TestCallbackError {
        _code: u32,
    }

    let mut protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("expected ProtectedBuffer creation to succeed");

    let result = protected_buffer.open(|_bytes| {
        Err(ProtectedBufferError::open_mut_callback_error(
            TestCallbackError { _code: 42 },
        ))
    });

    match result {
        Err(ProtectedBufferError::OpenMutCallbackError(inner)) => {
            let expected_inner = TestCallbackError { _code: 42 };
            let debug_str = format!("{:?}", inner);
            let expected_debug_str = format!("{:?}", expected_inner);

            assert_eq!(debug_str, expected_debug_str);
        }
        Err(other) => panic!("expected OpenMutCallbackError, got {:?}", other),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_propagates_protect_error_and_zeroizes_slice() {
    let mut protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("expected ProtectedBuffer creation to succeed");
    let protected_buffer_clone = protected_buffer.clone();
    let result = protected_buffer.open(|_bytes| {
        protected_buffer_clone.munmap();
        Ok(())
    });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ProtectedBufferError::ProtectionFailed)
    ));

    // Assert zeroization!
    assert!(protected_buffer.is_zeroized());
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_happypath() {
    let mut protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("expected ProtectedBuffer creation to succeed");

    protected_buffer
        .open(|bytes| {
            assert!(bytes.is_zeroized());
            Ok(())
        })
        .expect("Failed to open(..)");
}

// open_mut

#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_mut_propagates_unprotect_error() {
    let mut buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("expected ProtectedBuffer creation to succeed");

    buffer.munmap();

    let result = buffer.open_mut(|_| Ok(()));

    assert!(matches!(
        result,
        Err(ProtectedBufferError::UnprotectionFailed)
    ));
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_mut_fails_if_not_available() {
    let mut protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("Failed to create ProtectedBuffer");
    protected_buffer.fast_zeroize();

    let result = protected_buffer.open_mut(|_| Ok(()));

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ProtectedBufferError::PageNoLongerAvailable)
    ));
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_mut_propagates_callback_error() {
    #[derive(Debug)]
    struct TestCallbackError {
        _code: u32,
    }

    let mut protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("expected ProtectedBuffer creation to succeed");

    let result = protected_buffer.open_mut(|_bytes| {
        Err(ProtectedBufferError::open_mut_callback_error(
            TestCallbackError { _code: 42 },
        ))
    });

    match result {
        Err(ProtectedBufferError::OpenMutCallbackError(inner)) => {
            let expected_inner = TestCallbackError { _code: 42 };
            let debug_str = format!("{:?}", inner);
            let expected_debug_str = format!("{:?}", expected_inner);

            assert_eq!(debug_str, expected_debug_str);
        }
        Err(other) => panic!("expected OpenMutCallbackError, got {:?}", other),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_mut_propagates_protect_error_and_zeroizes_slice() {
    let mut protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("expected ProtectedBuffer creation to succeed");
    let protected_buffer_clone = protected_buffer.clone();
    let result = protected_buffer.open_mut(|_bytes| {
        protected_buffer_clone.munmap();
        Ok(())
    });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ProtectedBufferError::ProtectionFailed)
    ));

    // Assert zeroization!
    assert!(protected_buffer.is_zeroized());
}

// len

#[serial(rlimit)]
#[test]
fn test_protected_buffer_len() {
    let protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("Failed to create ProtectedBuffer");
    assert_eq!(protected_buffer.len(), 10);
}

// is_empty

#[serial(rlimit)]
#[test]
fn test_protected_buffer_is_empty_false() {
    let protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
        .expect("Failed to create ProtectedBuffer");
    assert!(!protected_buffer.is_empty());
}

#[serial(rlimit)]
#[test]
fn test_protected_buffer_is_empty_true() {
    let protected_buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 0)
        .expect("Failed to create ProtectedBuffer");
    assert!(protected_buffer.is_empty());
}
