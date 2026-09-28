// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether the encoding or the decoding branches on a byte, a digit or the
//! decoding's answer, or indexes memory by one of them.
//!
//! Memcheck decides, and it sees the run only when the binary is started under
//! it, which `scripts/constant-time.sh` does. Run one of these by hand and it
//! passes while measuring nothing, which is what the `ignore` keeps it from
//! doing under an ordinary suite. Only `Backend::Auto` is asked: the portable
//! backend promises nothing about time.

// glibc and not musl: `crabgrind` generates its bindings with `bindgen`, which
// opens libclang with `dlopen`, and a musl build script is a static binary
// where that call fails at run time rather than at link.
#![cfg(all(target_os = "linux", target_env = "gnu"))]

use crabgrind::memcheck::{MemState, mark_memory};
use redoubt_asm::Backend;

use crate::backend::{bytes_to_hex, hex_to_bytes};

/// Marks `bytes` undefined, which is how Memcheck is told they are secret.
///
/// The marking is refused when nothing is interpreting the process, and a run
/// that went unmarked would report clean while asking nothing.
fn as_secret(bytes: &[u8]) {
    mark_memory(bytes.as_ptr().cast(), bytes.len(), MemState::Undefined)
        .expect("the run is not under Valgrind, so nothing here is measured");
}

// ============================================================================
// the control
// ============================================================================

/// Stops at the first character that is not a digit, which is what the
/// decoding must not do.
fn stops_on_a_non_digit(digits: &[u8]) -> usize {
    digits
        .iter()
        .take_while(|digit| digit.is_ascii_hexdigit())
        .count()
}

/// Memcheck has to report this one.
///
/// A clean answer here means it is not watching, and then a clean answer from
/// the routines is the instrument standing somewhere else rather than a
/// property of the code.
#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_a_routine_that_stops_on_a_non_digit_branches_on_the_secret() {
    let digits = *b"9e41aFfA";

    as_secret(&digits);

    core::hint::black_box(stops_on_a_non_digit(&digits));
}

// ============================================================================
// bytes_to_hex
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_bytes_to_hex_branches_on_nothing() {
    let bytes = [0x9E_u8, 0x41, 0x0A, 0xFF, 0x00, 0x7C];
    let mut digits = [0_u8; 12];

    as_secret(&bytes);

    // SAFETY: `digits` is twice as long as `bytes`.
    unsafe { bytes_to_hex(Backend::Auto, &bytes, &mut digits) };

    core::hint::black_box(&digits);
}

// ============================================================================
// hex_to_bytes
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_hex_to_bytes_branches_on_nothing_when_every_digit_is_one() {
    let digits = *b"9e41aFfA0c";
    let mut bytes = [0_u8; 5];

    as_secret(&digits);

    // SAFETY: an even count, and `bytes` half as long.
    let accepted = unsafe { hex_to_bytes(Backend::Auto, &digits, &mut bytes) };

    core::hint::black_box((accepted, &bytes));
}

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_hex_to_bytes_branches_on_nothing_when_a_character_is_not_a_digit() {
    let digits = *b"9e41gFfA0c";
    let mut bytes = [0_u8; 5];

    as_secret(&digits);

    // SAFETY: an even count, and `bytes` half as long.
    let accepted = unsafe { hex_to_bytes(Backend::Auto, &digits, &mut bytes) };

    core::hint::black_box((accepted, &bytes));
}
