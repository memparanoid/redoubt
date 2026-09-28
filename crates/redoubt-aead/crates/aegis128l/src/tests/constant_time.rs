// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether the cipher branches on the key, the nonce or the message, or indexes
//! memory by one of them, anywhere but on the tag's answer, which the caller is
//! handed and which `declassify` says so.
//!
//! Memcheck decides, and it sees the run only when the binary is started under
//! it, which `scripts/constant-time.sh` does. Run one of these by hand and it
//! passes while measuring nothing, which is what the `ignore` keeps it from
//! doing under an ordinary suite.

// glibc and not musl: `crabgrind` generates its bindings with `bindgen`, which
// opens libclang with `dlopen`, and a musl build script is a static binary
// where that call fails at run time rather than at link.
#![cfg(all(target_os = "linux", target_env = "gnu"))]

use crabgrind::memcheck::{MemState, mark_memory};
use redoubt_aead_core::consts::aegis::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use redoubt_aead_core::{AeadDecrypt, AeadEncrypt};

use crate::Aegis128L;

/// Marks `bytes` undefined, which is how Memcheck is told they are secret.
///
/// The marking is refused when nothing is interpreting the process, and a run
/// that went unmarked would report clean while asking nothing.
fn as_secret(bytes: &[u8]) {
    mark_memory(bytes.as_ptr().cast(), bytes.len(), MemState::Undefined)
        .expect("the run is not under Valgrind, so nothing here is measured");
}

/// A message sealed under a key, and the tag it was sealed with.
fn sealed(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> ([u8; 200], [u8; TAG_SIZE]) {
    let mut data = [0x3C_u8; 200];
    let mut tag = [0_u8; TAG_SIZE];

    Aegis128L::new().encrypt(key, nonce, b"aad", &mut data, &mut tag);

    (data, tag)
}

// ============================================================================
// the control
// ============================================================================

/// Stops at the first key byte that is zero, which is what the cipher must not
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
// encrypt
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_encrypt_branches_on_nothing() {
    let key = [0x5A_u8; KEY_SIZE];
    let nonce = [0xA5_u8; NONCE_SIZE];
    let mut data = [0x3C_u8; 200];
    let mut tag = [0_u8; TAG_SIZE];

    as_secret(&key);
    as_secret(&nonce);
    as_secret(&data);

    Aegis128L::new().encrypt(&key, &nonce, b"aad", &mut data, &mut tag);

    core::hint::black_box((&data, &tag));
}

// ============================================================================
// decrypt
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_decrypt_branches_on_nothing_but_the_tag_when_it_matches() {
    let key = [0x5A_u8; KEY_SIZE];
    let nonce = [0xA5_u8; NONCE_SIZE];
    let (mut data, tag) = sealed(&key, &nonce);

    as_secret(&key);
    as_secret(&nonce);
    as_secret(&data);

    let answer = Aegis128L::new().decrypt(&key, &nonce, b"aad", &mut data, &tag);

    let _ = core::hint::black_box((answer, &data));
}

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_decrypt_branches_on_nothing_but_the_tag_when_it_does_not_match() {
    let key = [0x5A_u8; KEY_SIZE];
    let nonce = [0xA5_u8; NONCE_SIZE];
    let (mut data, mut tag) = sealed(&key, &nonce);

    tag[0] ^= 1;

    as_secret(&key);
    as_secret(&nonce);
    as_secret(&data);

    let answer = Aegis128L::new().decrypt(&key, &nonce, b"aad", &mut data, &tag);

    let _ = core::hint::black_box((answer, &data));
}
