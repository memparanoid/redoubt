// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use libseccomp::error::SeccompError;
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

pub fn block_syscall(name: &str) -> Result<(), SeccompError> {
    // Uncovered: the `?`. Nothing the caller passes reaches it: the context is
    // made from the default action alone.
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow)?;

    let syscall = ScmpSyscall::from_name(name)?;

    // Uncovered: the `?`. What the caller passes has already been resolved by
    // `from_name`, and the action is fixed here.
    filter.add_rule(ScmpAction::Errno(libc::EPERM), syscall)?;

    filter.load()
}

pub fn is_seccomp_available() -> bool {
    // SAFETY: the child only loads a filter and exits, and the parent only waits
    // for it.
    finalize_is_seccomp_available(unsafe { libc::fork() })
}

pub(crate) fn finalize_is_seccomp_available(forked: libc::pid_t) -> bool {
    match forked {
        -1 => false,
        0 => {
            let loaded = ScmpFilterContext::new(ScmpAction::Allow).and_then(|filter| filter.load());

            std::process::exit(i32::from(loaded.is_err()));
        }
        child => {
            let mut status: libc::c_int = 0;

            // SAFETY: `child` is this process's own child, and `status` a local.
            unsafe { libc::waitpid(child, &mut status, 0) };

            libc::WIFEXITED(status) & (libc::WEXITSTATUS(status) == 0)
        }
    }
}
