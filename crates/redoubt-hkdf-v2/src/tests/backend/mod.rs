// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! One file per function the seam declares, in the order it declares them.

mod asm;
mod rust;
mod shared;

/// The precondition every case in every file below rests on.
///
/// Where this build has no assembly the two backends are the same code, and
/// every pair of cases that found them agreeing would have proved nothing while
/// reading as though it had proved it twice.
///
/// Gating on `hkdf_asm` would be the build script agreeing with itself. This is
/// the other half of a pair: the build script decides, and this says what it was
/// meant to decide. A target that drops out of one and not the other lands here
/// as a failure instead of as a suite that quietly stopped comparing two
/// backends.
#[test]
#[cfg(all(
    not(target_os = "windows"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[expect(
    clippy::assertions_on_constants,
    reason = "a constant is what it asks about: whether this build has the assembly at all"
)]
fn test_this_target_has_the_assembly() {
    use crate::backend::HAS_ASM;

    assert!(
        HAS_ASM,
        "the cases below name two backends and this target has one"
    );
}
