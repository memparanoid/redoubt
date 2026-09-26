// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Which cipher sealed a message travels in the clear with the message, so
//! nothing here reads a secret.

// ============================================================================
// AeadAlgorithm::said
// ============================================================================

#[test]
#[ignore = "Reads no secret: it answers a discriminant."]
fn test_saying_an_algorithm_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AeadAlgorithm::read
// ============================================================================

#[test]
#[ignore = "Reads no secret: it answers the algorithm a byte names."]
fn test_reading_an_algorithm_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AeadAlgorithm::key_size
// ============================================================================

#[test]
#[ignore = "Reads no secret: it answers a width."]
fn test_sizing_a_key_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AeadAlgorithm::nonce_size
// ============================================================================

#[test]
#[ignore = "Reads no secret: it answers a width."]
fn test_sizing_a_nonce_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// AeadAlgorithm::tag_size
// ============================================================================

#[test]
#[ignore = "Reads no secret: it answers a width."]
fn test_sizing_a_tag_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// FastZeroizable for AeadAlgorithm
// ============================================================================

#[test]
#[ignore = "Reads no secret: it names the default algorithm."]
fn test_zeroizing_an_algorithm_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// BytesRequired for AeadAlgorithm
// ============================================================================

#[test]
#[ignore = "Reads no secret: it answers a width."]
fn test_sizing_an_algorithm_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Encode for AeadAlgorithm
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes a public byte."]
fn test_encoding_an_algorithm_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// Decode for AeadAlgorithm
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a public byte."]
fn test_decoding_an_algorithm_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// PreAlloc for AeadAlgorithm
// ============================================================================

#[test]
#[ignore = "Reads no secret: it does nothing."]
fn test_preallocating_an_algorithm_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// EncodeSlice for AeadAlgorithm
// ============================================================================

#[test]
#[ignore = "Reads no secret: it writes public bytes."]
fn test_encoding_algorithms_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// DecodeSlice for AeadAlgorithm
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads public bytes."]
fn test_decoding_algorithms_leaves_nothing() {
    // Intentionally empty.
}
