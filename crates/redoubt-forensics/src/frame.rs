// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! An operation run in a frame of its own, and frozen before that frame is
//! given back.

/// Runs `operation`, freezes what it left, and hands back what it returned.
///
/// The operation runs in a frame of its own that is never inlined, so whatever
/// the compiler folds into it lands there and not in the caller's frame. The
/// freeze runs inside that frame, before its epilogue restores anything, and
/// copies the window up to where the stack pointer stood here — so the frame
/// is in the copy although it is still live, and every register is as the
/// operation left it.
pub fn capture<R>(operation: impl FnOnce() -> R) -> R {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: one store of the stack pointer into this crate's own static, and
    // no register written.
    unsafe {
        core::arch::asm!(
            "mov qword ptr [rip + {top}], rsp",
            top = sym crate::window::TOP,
            options(nostack, preserves_flags),
        );
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: one store of the stack pointer into this crate's own static,
    // through two registers declared for it.
    unsafe {
        core::arch::asm!(
            "mov {sp}, sp",
            "adrp {page}, {top}",
            "str {sp}, [{page}, :lo12:{top}]",
            top = sym crate::window::TOP,
            sp = out(reg) _,
            page = out(reg) _,
            options(nostack, preserves_flags),
        );
    }

    on_its_own(operation)
}

/// Runs `operation` in a frame of its own, and freezes before that frame is
/// given back.
///
/// Never inlined: folded into the caller, the operation's locals would be the
/// caller's. The freeze comes before the epilogue, because the epilogue is
/// what puts back the registers this frame saved and the one it pushed only to
/// align the stack — and a register put back is a register whose last value is
/// gone.
#[inline(never)]
fn on_its_own<R>(operation: impl FnOnce() -> R) -> R {
    let out = operation();

    crate::freeze!();

    out
}
