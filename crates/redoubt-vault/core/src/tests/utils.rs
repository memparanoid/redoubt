// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// Check if seccomp is available by forking a child process that attempts to load a filter.
/// Returns true if seccomp works, false if running under QEMU or seccomp is unavailable.
#[cfg(target_os = "linux")]
pub fn is_seccomp_available() -> bool {
    use libseccomp::{ScmpAction, ScmpFilterContext};

    match unsafe { libc::fork() } {
        -1 => {
            // Fork failed
            eprintln!("Failed to fork for seccomp check");
            false
        }
        0 => {
            // Child process: try to load a dummy seccomp filter
            let result = ScmpFilterContext::new(ScmpAction::Allow).and_then(|filter| filter.load());

            // Exit with 0 if successful, 1 if failed
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
        child_pid => {
            // Parent process: wait for child and check exit status
            let mut status: libc::c_int = 0;
            unsafe {
                libc::waitpid(child_pid, &mut status, 0);
            }

            // Check if child exited successfully (exit code 0)
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        }
    }
}

#[cfg(target_os = "linux")]
fn block_syscall(name: &str) {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

    let mut filter = ScmpFilterContext::new(ScmpAction::Allow).expect("Failed to create filter");
    filter
        .add_rule(
            ScmpAction::Errno(libc::EPERM),
            ScmpSyscall::from_name(name).expect("Failed to from_name(..)"),
        )
        .expect("Failed to add rule");
    filter.load().expect("Failed to load seccomp filter");
}

#[cfg(target_os = "linux")]
pub fn block_mprotect() {
    block_syscall("mprotect");
}

#[cfg(target_os = "linux")]
pub fn block_mlock() {
    block_syscall("mlock");
}

#[cfg(target_os = "linux")]
pub fn block_munlock() {
    block_syscall("munlock");
}

#[cfg(target_os = "linux")]
pub fn block_madvise() {
    block_syscall("madvise");
}

/// Blocks the getrandom syscall (primary entropy source on Linux).
#[cfg(target_os = "linux")]
pub fn block_getrandom() {
    block_syscall("getrandom");
}

/// Blocks the read syscall (used by getrandom crate to read from /dev/urandom fallback).
#[cfg(target_os = "linux")]
pub fn block_read() {
    block_syscall("read");
}

/// Blocks the openat syscall (used by getrandom crate to open /dev/urandom fallback).
/// Together with block_getrandom() and block_read(), this completely blocks all entropy sources.
#[cfg(target_os = "linux")]
pub fn block_openat() {
    block_syscall("openat");
}

pub fn run_test_as_subprocess(test_name: &str) -> Option<i32> {
    let exe = std::env::current_exe().expect("Failed to get current exe");
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            test_name,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .output()
        .expect("Failed to run subprocess");

    // Print subprocess output for debugging
    if !output.stdout.is_empty() {
        println!(
            "SUBPROCESS STDOUT:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    if !output.stderr.is_empty() {
        eprintln!(
            "SUBPROCESS STDERR:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    if output.stdout.starts_with(b"\nrunning 0 tests") {
        return Some(-1);
    }

    output.status.code()
}

#[test]
fn test_run_test_as_subprocess_fails_if_test_does_not_exist() {
    let exit_code = run_test_as_subprocess("uknown::test");
    assert_eq!(exit_code, Some(-1), "test should have failed");
}
