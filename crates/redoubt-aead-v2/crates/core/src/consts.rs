// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The widths each algorithm works in.
//!
//! Here rather than beside each implementation, because a width outlives it: a
//! tag is sixteen bytes to what computes it and to what compares it, and a key
//! is thirty-two to the cipher and to the AEAD above.

/// ChaCha20 and its two relatives.
pub mod chacha {
    /// Bytes of key, for all three.
    pub const KEY_SIZE: usize = 32;

    /// Bytes of nonce, RFC 8439: twelve, with a four-byte counter.
    pub const NONCE_SIZE: usize = 12;

    /// Bytes of nonce, Bernstein's original: eight, with an eight-byte
    /// counter. What OpenSSH speaks.
    pub const BERNSTEIN_NONCE_SIZE: usize = 8;

    /// Bytes of nonce, XChaCha20: twenty-four, of which the first sixteen go
    /// to HChaCha20 and the rest to the ChaCha20 underneath.
    pub const XNONCE_SIZE: usize = 24;

    /// Bytes of nonce HChaCha20 takes, which is the front of an XChaCha20 one.
    pub const HNONCE_SIZE: usize = 16;

    /// Bytes of keystream a single ChaCha20 block yields.
    pub const BLOCK_SIZE: usize = 64;
}

/// Poly1305.
pub mod poly1305 {
    /// Bytes of key: `r` and `s`, sixteen each.
    pub const KEY_SIZE: usize = 32;

    /// Bytes the accumulator eats at a time.
    pub const BLOCK_SIZE: usize = 16;

    /// Bytes of tag.
    pub const TAG_SIZE: usize = 16;
}

/// AEGIS-128L.
pub mod aegis {
    /// Bytes of key.
    pub const KEY_SIZE: usize = 16;

    /// Bytes of nonce.
    pub const NONCE_SIZE: usize = 16;

    /// Bytes of tag.
    pub const TAG_SIZE: usize = 16;
}
