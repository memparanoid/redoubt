// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether the authenticator branches on the key or the message, or indexes
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
use redoubt_aead_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};
use redoubt_asm::Backend;

use crate::backend::{finalize, init, update};
use crate::consts::{ACC_WORDS, R_WORDS};

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

/// Stops at the first key byte that is zero, which is what an authenticator
/// must not do.
fn stops_on_the_key(key: &[u8; KEY_SIZE]) -> usize {
    key.iter().take_while(|byte| **byte != 0).count()
}

/// Memcheck has to report this one.
///
/// A clean answer here means it is not watching, and then a clean answer from
/// the authenticator is the instrument standing somewhere else rather than a
/// property of the code.
#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_a_routine_that_stops_on_the_key_branches_on_the_secret() {
    let key = [0x5A_u8; KEY_SIZE];

    as_secret(&key);

    core::hint::black_box(stops_on_the_key(&key));
}

// ============================================================================
// init, update, finalize
// ============================================================================

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_init_branches_on_nothing() {
    let key = [0x5A_u8; KEY_SIZE];
    let mut r = [0_u64; R_WORDS];
    let mut s = [0_u8; BLOCK_SIZE];

    as_secret(&key);

    init(Backend::Auto, &mut r, &mut s, &key);

    core::hint::black_box((&r, &s));
}

#[test]
#[ignore = "Memcheck decides; `scripts/constant-time.sh` is what runs it"]
fn test_the_chosen_update_and_finalize_branch_on_nothing() {
    let key = [0x5A_u8; KEY_SIZE];
    let said = [0x3C_u8; 200];
    let mut r = [0_u64; R_WORDS];
    let mut s = [0_u8; BLOCK_SIZE];
    let mut acc = [0_u64; ACC_WORDS];
    let mut block = [0_u8; BLOCK_SIZE];
    let mut filled = 0_usize;
    let mut tag = [0_u8; TAG_SIZE];

    as_secret(&key);
    as_secret(&said);

    init(Backend::Auto, &mut r, &mut s, &key);
    update(
        Backend::Auto,
        &mut acc,
        &r,
        &mut block,
        &mut filled,
        &said[..77],
    );
    finalize(Backend::Auto, &mut acc, &r, &s, &said[77..], &mut tag);

    core::hint::black_box(&tag);
}
