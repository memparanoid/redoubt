// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

pub(crate) fn block_getrandom() {
    let mut filter =
        ScmpFilterContext::new(ScmpAction::Allow).expect("the seccomp filter could not be made");

    filter
        .add_rule(
            ScmpAction::Errno(libc::EPERM),
            ScmpSyscall::from_name("getrandom").expect("seccomp does not know getrandom"),
        )
        .expect("the rule refusing getrandom could not be added");

    filter
        .load()
        .expect("the seccomp filter could not be loaded");
}
