// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether the cipher branches on the key, the nonce or the message, or indexes
//! memory by one of them.
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
use redoubt_aead_core::consts::chacha::{HNONCE_SIZE, KEY_SIZE, XNONCE_SIZE};
use redoubt_asm::Backend;

use crate::backend::{subkey, xor, xxor};

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

/// Stops at the first key byte that is zero, which is what a cipher must not
/// do.
fn stops_on_the_key(key: &[u8; KEY_SIZE]) -> usize {
    key.iter().take_while(|byte| **byte != 0).count()
}

/// Memcheck has to report this one.
///
/// A clean answer here means it is not watching, and then a clean answer from
/// the cipher is the instrument standing somewhere else rather than a property
/// of the code.
#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_a_routine_that_stops_on_the_key_branches_on_the_secret() {
    let key = [0x5A_u8; KEY_SIZE];

    as_secret(&key);

    core::hint::black_box(stops_on_the_key(&key));
}

// ============================================================================
// subkey
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_subkey_branches_on_nothing() {
    let key = [0x5A_u8; KEY_SIZE];
    let nonce = [0xA5_u8; HNONCE_SIZE];
    let mut out = [0_u8; KEY_SIZE];

    as_secret(&key);
    as_secret(&nonce);

    subkey(Backend::Auto, &mut out, &key, &nonce);

    core::hint::black_box(&out);
}

// ============================================================================
// xor
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_xor_under_a_twelve_byte_nonce_branches_on_nothing() {
    let key = [0x5A_u8; KEY_SIZE];
    let nonce = [0xA5_u8; 12];
    let mut data = [0x3C_u8; 200];

    as_secret(&key);
    as_secret(&nonce);
    as_secret(&data);

    xor(Backend::Auto, &key, &nonce, 1, &mut data);

    core::hint::black_box(&data);
}

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_xor_under_an_eight_byte_nonce_branches_on_nothing() {
    let key = [0x5A_u8; KEY_SIZE];
    let nonce = [0xA5_u8; 8];
    let mut data = [0x3C_u8; 200];

    as_secret(&key);
    as_secret(&nonce);
    as_secret(&data);

    xor(Backend::Auto, &key, &nonce, 1, &mut data);

    core::hint::black_box(&data);
}

// ============================================================================
// xxor
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_xxor_branches_on_nothing() {
    let key = [0x5A_u8; KEY_SIZE];
    let nonce = [0xA5_u8; XNONCE_SIZE];
    let mut data = [0x3C_u8; 200];

    as_secret(&key);
    as_secret(&nonce);
    as_secret(&data);

    xxor(Backend::Auto, &key, &nonce, 1, &mut data);

    core::hint::black_box(&data);
}
