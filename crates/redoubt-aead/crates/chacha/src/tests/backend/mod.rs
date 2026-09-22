// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! One folder per thing that can be called.
//!
//! `rust` and `asm` are the two implementations; `seam` is what chooses between
//! them. A test belongs where the code it exercises lives: a property of the
//! Rust state goes to `rust`, what the assembly leaves behind goes to `asm`,
//! and anything asked of both backends goes through `seam`.

#[cfg(chacha_asm)]
mod asm;
mod helpers;
mod rust;
mod seam;

/// The precondition every case under `seam` rests on, which is why it is here
/// rather than beside them.
///
/// The two backends are the same code where the target has no assembly, and a
/// pair of cases that found them agreeing there would have proved nothing about
/// either — while reading as though it had proved it twice.
///
/// Gating on `chacha_asm` would be the build script agreeing with itself. This
/// is the other half of a pair: the build script decides, and this says what it
/// was meant to decide. A target that drops out of one and not the other lands
/// here as a failure instead of as a suite that quietly stopped comparing two
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
