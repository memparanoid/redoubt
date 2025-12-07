// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::cell::Cell;

use serial_test::serial;

use memzer::{FastZeroizable, ZeroizationProbe};

use crate::error::{LibcPageError, ProtectedBufferError};
use crate::protected::{AbortCode, ProtectedBuffer, ProtectionStrategy, TryCreateStage};
use crate::traits::Buffer;
use crate::utils::fill_with_pattern;

#[cfg(target_os = "linux")]
fn block_mem_syscalls() {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

    let mut filter = ScmpFilterContext::new(ScmpAction::Allow).expect("Failed to create filter");

    for syscall in &["mprotect", "mlock", "munlock", "madvise"] {
        filter
            .add_rule(
                ScmpAction::Errno(libc::EPERM),
                ScmpSyscall::from_name(syscall).unwrap(),
            )
            .expect("Failed to add rule");
    }

    filter.load().expect("Failed to load seccomp filter");
}

/// Runs a closure in a forked child process and returns the exit code.
///
/// # Why fork is needed
///
/// Some tests need process isolation because:
/// - seccomp filters are process-wide and cannot be removed once applied
/// - We need to test error paths that would terminate the process (abort/exit)
/// - Tests that manipulate rlimits or memory protections shouldn't affect other tests
///
/// # Why explicit _exit is needed
///
/// Functions like `try_create` return `Result` instead of aborting on error.
/// The test closure must explicitly call `libc::_exit(code)` to signal the result
/// back to the parent process. Without an explicit exit, the closure would return
/// normally and the child would exit with code 0, making the test meaningless.
///
/// # Returns
///
/// - `Some(code)` if child exited normally with that code
/// - `None` if child was killed by a signal (e.g., SIGABRT, SIGSEGV)
#[cfg(target_os = "linux")]
fn run_in_fork<F>(f: F) -> Option<isize>
where
    F: FnOnce(),
{
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => panic!("fork failed"),
        0 => {
            f();
            std::process::exit(0);
        }
        child_pid => {
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };

            if libc::WIFEXITED(status) {
                Some(libc::WEXITSTATUS(status) as isize)
            } else {
                None // killed by signal
            }
        }
    }
}

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

fn run_protected_buffer_open_happy_path_test(strategy: ProtectionStrategy) {
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

    // Not zeroized
    {
        let callback_executed = Cell::new(false);
        protected_buffer
            .open(|bytes| {
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

    // Not zeroized
    {
        let callback_executed = Cell::new(false);
        protected_buffer
            .open(|bytes| {
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
fn test_protected_buffer_try_create_reports_page_creation_failed_error() {
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
        Err(ProtectedBufferError::LibcPage(LibcPageError::PageCreationFailed))
    ));

    unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) };
}

#[cfg(target_os = "linux")]
#[serial(rlimit)]
#[test]
fn test_protected_buffer_try_create_reports_lock_failed_error() {
    // try_create returns Result, it does NOT abort on error.
    // We must explicitly check the error type and exit with a code.
    let exit_code = run_in_fork(|| {
        let result = ProtectedBuffer::try_create_with(
            ProtectionStrategy::MemProtected,
            10,
            &mut |stage, _pb| {
                if matches!(stage, TryCreateStage::Lock) {
                    block_mem_syscalls();
                }
            },
        );

        match result {
            Err(ProtectedBufferError::LibcPage(ref libc_err)) => {
                ProtectedBuffer::abort_from_error(libc_err)
            }
            Err(_) => {} // Other error type
            Ok(_) => {}  // Should not succeed (will exit with code 0)
        }
    });

    assert_eq!(
        exit_code,
        Some(AbortCode::LockFailed as isize),
        "Expected LockFailed error"
    );
}

#[cfg(target_os = "linux")]
#[serial(rlimit)]
#[test]
fn test_protected_buffer_try_create_reports_protection_failed_error() {
    // try_create returns Result, it does NOT abort on error.
    // We must explicitly check the error type and exit with a code.
    let exit_code = run_in_fork(|| {
        let result = ProtectedBuffer::try_create_with(
            ProtectionStrategy::MemProtected,
            10,
            &mut |stage, _pb| {
                if matches!(stage, TryCreateStage::Protect) {
                    block_mem_syscalls();
                }
            },
        );

        match result {
            Err(ProtectedBufferError::LibcPage(ref libc_err @ LibcPageError::ProtectionFailed)) => {
                ProtectedBuffer::abort_from_error(libc_err)
            }
            Err(_) => {} // Other error type
            Ok(_) => {}  // Should not succeed (will exit with code 0)
        }
    });

    assert_eq!(
        exit_code,
        Some(AbortCode::ProtectionFailed as isize),
        "Expected ProtectionFailed error"
    );
}

#[cfg(target_os = "linux")]
#[serial(rlimit)]
#[test]
fn test_protected_buffer_propagates_fill_with_pattern_0_error() {
    // try_create returns Result, it does NOT abort on error.
    // We must explicitly check the error type and exit with a code.
    let exit_code = run_in_fork(|| {
        let result = ProtectedBuffer::try_create_with(
            ProtectionStrategy::MemProtected,
            10,
            &mut |stage, _pb| {
                if matches!(stage, TryCreateStage::FillWithPattern0) {
                    block_mem_syscalls();
                }
            },
        );

        match result {
            Err(ProtectedBufferError::LibcPage(ref libc_err @ LibcPageError::UnprotectionFailed)) => {
                // The first syscall of `FillWithPattern0` stage is unprotect
                ProtectedBuffer::abort_from_error(libc_err)
            }
            Err(_) => {} // Other error type
            Ok(_) => {}  // Should not succeed (will exit with code 0)
        }
    });

    assert_eq!(
        exit_code,
        Some(AbortCode::UnprotectionFailed as isize),
        "Expected UnprotectionFailed error"
    );
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

#[cfg(target_os = "linux")]
#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_aborts_on_unprotect_error() {
    let exit_code = run_in_fork(|| {
        let mut buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
            .expect("expected ProtectedBuffer creation to succeed");

        block_mem_syscalls();

        let _ = buffer.open(|_| Ok(()));
    });

    assert_eq!(
        exit_code,
        Some(AbortCode::UnprotectionFailed as isize),
        "Expected UnprotectionFailed error"
    );
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
        Err(ProtectedBufferError::callback_error(TestCallbackError {
            _code: 42,
        }))
    });

    match result {
        Err(ProtectedBufferError::CallbackError(inner)) => {
            let debug_str = format!("{:?}", inner);

            let expected_inner = TestCallbackError { _code: 42 };
            let expected_debug_str = format!("{:?}", expected_inner);

            assert_eq!(debug_str, expected_debug_str);
        }
        Err(other) => panic!("expected CallbackError, got {:?}", other),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

#[cfg(target_os = "linux")]
#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_aborts_on_protect_error_and_zeroizes_slice() {
    let exit_code = run_in_fork(|| {
        let mut buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
            .expect("expected ProtectedBuffer creation to succeed");

        let result = buffer.open(|_| {
            block_mem_syscalls();
            Ok(())
        });

        match result {
            Err(ProtectedBufferError::LibcPage(ref libc_err @ LibcPageError::ProtectionFailed)) => {
                // Assert zeroization!
                assert!(buffer.is_zeroized());
                ProtectedBuffer::abort_from_error(libc_err)
            }
            Err(_) => {} // Other error type
            Ok(_) => {}  // Should not succeed (will exit with code 0)
        }
    });

    assert_eq!(
        exit_code,
        Some(AbortCode::ProtectionFailed as isize),
        "Expected ProtectionFailed error"
    );
}

// open_mut

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

#[cfg(target_os = "linux")]
#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_mut_aborts_on_unprotect_error() {
    let exit_code = run_in_fork(|| {
        let mut buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
            .expect("expected ProtectedBuffer creation to succeed");

        block_mem_syscalls();

        let _ = buffer.open_mut(|_| Ok(()));
    });

    assert_eq!(
        exit_code,
        Some(AbortCode::UnprotectionFailed as isize),
        "Expected UnprotectionFailed error"
    );
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
        Err(ProtectedBufferError::callback_error(TestCallbackError {
            _code: 42,
        }))
    });

    match result {
        Err(ProtectedBufferError::CallbackError(inner)) => {
            let debug_str = format!("{:?}", inner);

            let expected_inner = TestCallbackError { _code: 42 };
            let expected_debug_str = format!("{:?}", expected_inner);

            assert_eq!(debug_str, expected_debug_str);
        }
        Err(other) => panic!("expected CallbackError, got {:?}", other),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

#[cfg(target_os = "linux")]
#[serial(rlimit)]
#[test]
fn test_protected_buffer_open_mut_aborts_on_protect_error_and_zeroizes_slice() {
    let exit_code = run_in_fork(|| {
        let mut buffer = ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 10)
            .expect("expected ProtectedBuffer creation to succeed");

        let result = buffer.open_mut(|_| {
            block_mem_syscalls();
            Ok(())
        });

        match result {
            Err(ProtectedBufferError::LibcPage(ref libc_err @ LibcPageError::ProtectionFailed)) => {
                // Assert zeroization!
                assert!(buffer.is_zeroized());
                ProtectedBuffer::abort_from_error(libc_err)
            }
            Err(_) => {} // Other error type
            Ok(_) => {}  // Should not succeed (will exit with code 0)
        }
    });

    assert_eq!(
        exit_code,
        Some(AbortCode::ProtectionFailed as isize),
        "Expected ProtectionFailed error"
    );
}


// open / open_mut happy paths
#[serial(rlimit)]
#[test]
fn test_protected_open_happy_paths() {
    run_protected_buffer_open_happy_path_test(ProtectionStrategy::MemProtected);
    run_protected_buffer_open_happy_path_test(ProtectionStrategy::MemNonProtected);
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
