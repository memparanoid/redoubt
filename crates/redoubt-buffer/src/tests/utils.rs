// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Test utilities for redoubt-buffer.

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
            let result = ScmpFilterContext::new(ScmpAction::Allow)
                .and_then(|filter| filter.load());

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

/// Runs an ignored test as a subprocess and returns its exit code.
#[cfg(target_os = "linux")]
pub fn run_test_as_subprocess(test_name: &str) -> Option<i32> {
    let exe = std::env::current_exe().expect("Failed to current_exe()");
    let status = std::process::Command::new(exe)
        .args([
            "--exact",
            test_name,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .status()
        .expect("Failed to run subprocess");

    status.code()
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
pub fn block_mlock() {
    block_syscall("mlock");
}

#[cfg(target_os = "linux")]
pub fn block_mprotect() {
    block_syscall("mprotect");
}

#[cfg(target_os = "linux")]
pub fn block_madvise() {
    block_syscall("madvise");
}
