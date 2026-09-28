// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether the hash, the authenticator or the derivation branches on the key,
//! the salt, the info or the message, or indexes memory by one of them.
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

use crate::backend::{hkdf_sha256, hmac_sha256, sha256_hash};
use crate::consts::HASH_SIZE;

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

/// Stops at the first key byte that is zero, which is what a derivation must
/// not do.
fn stops_on_the_key(key: &[u8]) -> usize {
    key.iter().take_while(|byte| **byte != 0).count()
}

/// Memcheck has to report this one.
///
/// A clean answer here means it is not watching, and then a clean answer from
/// the routines is the instrument standing somewhere else rather than a
/// property of the code.
#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_a_routine_that_stops_on_the_key_branches_on_the_secret() {
    let key = [0x5A_u8; 32];

    as_secret(&key);

    core::hint::black_box(stops_on_the_key(&key));
}

// ============================================================================
// sha256_hash
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_sha256_hash_branches_on_nothing() {
    let data = [0x3C_u8; 200];
    let mut out = [0_u8; HASH_SIZE];

    as_secret(&data);

    sha256_hash(Backend::Auto, &data, &mut out);

    core::hint::black_box(&out);
}

// ============================================================================
// hmac_sha256
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_hmac_sha256_branches_on_nothing() {
    let key = [0x5A_u8; 32];
    let data = [0x3C_u8; 200];
    let mut out = [0_u8; HASH_SIZE];

    as_secret(&key);
    as_secret(&data);

    hmac_sha256(Backend::Auto, &key, &data, &mut out);

    core::hint::black_box(&out);
}

// ============================================================================
// hkdf_sha256
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_hkdf_sha256_branches_on_nothing() {
    let salt = [0xA5_u8; 32];
    let ikm = [0x5A_u8; 64];
    let info = [0x3C_u8; 40];
    let mut okm = [0_u8; 100];

    as_secret(&salt);
    as_secret(&ikm);
    as_secret(&info);

    hkdf_sha256(Backend::Auto, &salt, &ikm, &info, &mut okm);

    core::hint::black_box(&okm);
}
