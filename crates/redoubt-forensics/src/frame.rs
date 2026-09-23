// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! An operation run in a frame of its own, and frozen the moment it returns.

/// Runs `operation`, freezes what it left, and hands back what it returned.
///
/// The operation runs in a frame of its own that is never inlined, so whatever
/// the compiler folds into it lands in that frame, and the frame is released —
/// inside the window [`crate::freeze`] copies — by the time the freeze runs.
/// Nothing runs between its return and the freeze.
pub fn capture<R>(operation: impl FnOnce() -> R) -> R {
    let out = on_its_own(operation);

    crate::freeze!();

    out
}

/// Runs `operation` in a frame of its own.
///
/// Never inlined: folded into the caller, the operation's locals would be the
/// caller's, above the stack pointer the freeze runs at, where its copy never
/// reaches.
#[inline(never)]
pub(crate) fn on_its_own<R>(operation: impl FnOnce() -> R) -> R {
    operation()
}
