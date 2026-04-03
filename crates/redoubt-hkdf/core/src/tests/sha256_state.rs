// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for Sha256State streaming API (update/finalize).
//!
//! These exercise the partial buffer branch (`buffer_len > 0` in update())
//! which requires multiple update() calls with non-block-aligned data.

use crate::sha256::Sha256State;

#[test]
fn test_sha256_streaming_partial_buffer() {
    // Two updates where the first leaves a partial buffer (30 < 64)
    let part1 = b"abcdbcdecdefdefgefghfghighijhijk"; // 30 bytes
    let part2 = b"ijkljklmklmnlmnomnopnopq"; // 26 bytes (total = 56)

    let mut streaming_digest = [0u8; 32];
    let mut state = Sha256State::new();
    state.update(part1);
    state.update(part2);
    state.finalize(&mut streaming_digest);

    // Reference: single-call hash of the same 56-byte message
    let mut reference_digest = [0u8; 32];
    let mut ref_state = Sha256State::new();
    ref_state.hash(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        &mut reference_digest,
    );

    assert_eq!(
        streaming_digest, reference_digest,
        "Streaming SHA-256 with partial buffer should match single-call hash"
    );
}

#[test]
fn test_sha256_streaming_multiple_updates() {
    // Many small updates that cross block boundaries multiple times
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(msg.len(), 112);

    // Feed in chunks of 15 bytes (not aligned to 64-byte blocks)
    let mut streaming_digest = [0u8; 32];
    let mut state = Sha256State::new();
    for chunk in msg.chunks(15) {
        state.update(chunk);
    }
    state.finalize(&mut streaming_digest);

    // Reference: single-call hash
    let mut reference_digest = [0u8; 32];
    let mut ref_state = Sha256State::new();
    ref_state.hash(msg, &mut reference_digest);

    assert_eq!(
        streaming_digest, reference_digest,
        "Streaming SHA-256 with multiple small updates should match single-call hash"
    );
}
