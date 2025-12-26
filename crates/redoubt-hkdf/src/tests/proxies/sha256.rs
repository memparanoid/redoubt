// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! SHA-256 compression and hash functions

/// SHA-256 compression function (single block)
///
/// Updates hash state `h` with a single 512-bit message block.
///
/// # Arguments
/// * `h` - Hash state (8 × u32, input/output)
/// * `block` - Message block (64 bytes)
#[cfg(all(feature = "asm", is_asm_eligible))]
pub(crate) fn sha256_compress_block(h: &mut [u32; 8], block: &[u8; 64]) {
    unsafe {
        crate::asm::sha256_compress_block(h.as_mut_ptr(), block.as_ptr());
    }
}

/// SHA-256 compression function (Rust fallback)
#[cfg(not(all(feature = "asm", is_asm_eligible)))]
pub(crate) fn sha256_compress_block(h: &mut [u32; 8], block: &[u8; 64]) {
    use crate::rust::sha256::Sha256State;

    let mut state = Sha256State::new();
    state.compress_block(h, block);
}

/// SHA-256 hash function (arbitrary-length message)
///
/// Computes SHA-256 digest of input message.
///
/// # Arguments
/// * `data` - Input message (arbitrary length)
/// * `out` - Output digest (32 bytes)
#[cfg(all(feature = "asm", is_asm_eligible))]
pub(crate) fn sha256_hash(data: &[u8], out: &mut [u8; 32]) {
    unsafe {
        crate::asm::sha256_hash(data.as_ptr(), data.len(), out.as_mut_ptr());
    }
}

/// SHA-256 hash function (Rust fallback)
#[cfg(not(all(feature = "asm", is_asm_eligible)))]
pub(crate) fn sha256_hash(data: &[u8], out: &mut [u8; 32]) {
    use crate::rust::sha256::Sha256State;

    let mut state = Sha256State::new();
    state.hash(data, out);
}
