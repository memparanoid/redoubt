// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether the comparison branches on what the two runs hold.
//!
//! # How the question is asked
//!
//! Memcheck tracks which bytes are undefined and reports every conditional
//! jump and every memory index that depends on one. Marking a buffer undefined
//! is therefore marking it secret: what comes back is a list of the places the
//! comparison let its contents decide where to go.
//!
//! # Nothing here asserts
//!
//! Memcheck is what decides, and it sees the run only when the binary is
//! started under it, which `scripts/constant-time.sh` does. Run one of these
//! by hand and it passes while measuring nothing, which is what the `ignore`
//! keeps it from doing under an ordinary suite.

// glibc and not musl: `crabgrind` generates its bindings with `bindgen`, which
// opens libclang with `dlopen`, and a musl build script is a static binary
// where that call fails at run time rather than at link.
#![cfg(all(target_os = "linux", target_env = "gnu"))]

use crabgrind::memcheck::{MemState, mark_memory};
use redoubt_asm::Backend;

use crate::eq::constant_time_eq_using;

const WIDTH: usize = 16;

/// Two runs differing in their last byte, which is the case a short circuit
/// takes longest to reach.
fn pair() -> ([u8; WIDTH], [u8; WIDTH]) {
    let mut a = [0x5A_u8; WIDTH];
    let b = [0x5A_u8; WIDTH];

    a[WIDTH - 1] ^= 0xFF;

    (a, b)
}

/// Marks both runs undefined, which is how Memcheck is told they are secret.
///
/// The marking is refused when nothing is interpreting the process, and a run
/// that went unmarked would report clean while asking nothing.
fn as_secret(a: &[u8], b: &[u8]) {
    mark_memory(a.as_ptr().cast(), a.len(), MemState::Undefined)
        .expect("the run is not under Valgrind, so nothing here is measured");
    mark_memory(b.as_ptr().cast(), b.len(), MemState::Undefined)
        .expect("the run is not under Valgrind, so nothing here is measured");
}

// ============================================================================
// the control
// ============================================================================

/// An equality that returns as soon as it finds a difference, which is what
/// this comparison must not do.
fn short_circuiting_eq(a: &[u8], b: &[u8]) -> bool {
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return false;
        }
    }

    true
}

/// Memcheck has to report this one.
///
/// A clean answer here means it is not watching, and then a clean answer from
/// a real comparison is the instrument standing somewhere else rather than a
/// property of the code.
#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_a_short_circuiting_eq_branches_on_the_secret() {
    let (a, b) = pair();

    as_secret(&a, &b);

    core::hint::black_box(short_circuiting_eq(&a, &b));
}

// ============================================================================
// constant_time_eq
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_rust_eq_branches_on_nothing_but_its_answer() {
    let (a, b) = pair();

    as_secret(&a, &b);

    core::hint::black_box(constant_time_eq_using(Backend::Rust, &a, &b));
}

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_eq_branches_on_nothing_but_its_answer() {
    let (a, b) = pair();

    as_secret(&a, &b);

    core::hint::black_box(constant_time_eq_using(Backend::Auto, &a, &b));
}
