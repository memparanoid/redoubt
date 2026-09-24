// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Test utilities for redoubt-buffer.

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
