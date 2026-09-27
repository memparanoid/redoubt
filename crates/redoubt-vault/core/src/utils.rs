// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::sync::atomic::AtomicUsize;

/// The uid the next box made in this process takes.
pub(crate) static CIPHERBOX_UID: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
pub(crate) fn this_process() -> u32 {
    // SAFETY: it reads the caller's own identity, takes no pointer and cannot
    // fail.
    unsafe { libc::getpid() as u32 }
}

#[cfg(not(unix))]
pub(crate) fn this_process() -> u32 {
    0
}
