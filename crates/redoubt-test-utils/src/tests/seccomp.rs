// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::error::Error;

use crate::seccomp::{block_syscall, finalize_is_seccomp_available, is_seccomp_available};
use crate::subprocess::run_test_as_subprocess;

// ============================================================================
// block_syscall
// ============================================================================

#[test]
fn test_block_syscall_propagates_a_name_seccomp_does_not_know() {
    assert!(block_syscall("not_a_syscall").is_err());
}

#[test]
fn test_block_syscall_refuses_the_syscall_it_names() {
    assert_eq!(
        run_test_as_subprocess("tests::seccomp::subprocess_mlock_refused"),
        Some(0)
    );
}

#[test]
fn test_block_syscall_leaves_every_other_syscall_alone() {
    assert_eq!(
        run_test_as_subprocess("tests::seccomp::subprocess_mlock_granted_with_munlock_refused"),
        Some(0)
    );
}

// ============================================================================
// is_seccomp_available
// ============================================================================

#[test]
fn test_is_seccomp_available_agrees_with_the_kernel() -> Result<(), Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let kernel_has_it = status.lines().any(|line| line.starts_with("Seccomp:"));

    assert_eq!(is_seccomp_available(), kernel_has_it);

    Ok(())
}

// ============================================================================
// finalize_is_seccomp_available
// ============================================================================

#[test]
fn test_finalize_is_seccomp_available_returns_false_when_the_fork_failed() {
    assert!(!finalize_is_seccomp_available(-1));
}

// ==============================
// ===== Subprocess tests =======
// ==============================

#[test]
#[ignore]
fn subprocess_mlock_refused() -> Result<(), Box<dyn Error>> {
    block_syscall("mlock")?;

    let held = [0_u8; 64];

    // SAFETY: the range is a local of this frame, live across the call.
    let answered = unsafe { libc::mlock(held.as_ptr().cast(), held.len()) };

    assert_eq!(answered, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );

    Ok(())
}

#[test]
#[ignore]
fn subprocess_mlock_granted_with_munlock_refused() -> Result<(), Box<dyn Error>> {
    block_syscall("munlock")?;

    let held = [0_u8; 64];

    // SAFETY: the range is a local of this frame, live across the call.
    assert_eq!(unsafe { libc::mlock(held.as_ptr().cast(), held.len()) }, 0);

    Ok(())
}
