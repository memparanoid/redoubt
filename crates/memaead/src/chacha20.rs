// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ChaCha20 stream cipher implementation (RFC 8439)
//!
//! This module provides the core ChaCha20 primitives:
//! - `quarter_round`: The basic mixing operation
//! - `chacha20_block`: Generates a 64-byte keystream block
//! - `chacha20_crypt`: XORs data with keystream (encrypt/decrypt)

/// ChaCha20 quarter round operation (RFC 8439 Section 2.1)
///
/// Operates on 4 words of the state matrix, applying:
/// a += b; d ^= a; d <<<= 16;
/// c += d; b ^= c; b <<<= 12;
/// a += b; d ^= a; d <<<= 8;
/// c += d; b ^= c; b <<<= 7;
#[inline(always)]
pub(crate) fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Initialize ChaCha20 state matrix from key, nonce, and counter (RFC 8439 Section 2.3)
///
/// State layout (4x4 matrix of u32):
/// ```text
/// cccccccc  cccccccc  cccccccc  cccccccc
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
/// bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
/// ```
/// Where c = constant, k = key, b = block counter, n = nonce
#[inline]
fn init_state(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    let mut state = [0u32; 16];

    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (8 words)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }

    // Counter
    state[12] = counter;

    // Nonce (3 words)
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    state
}

/// Generate a 64-byte ChaCha20 keystream block (RFC 8439 Section 2.3)
///
/// Runs 20 rounds (10 iterations of column + diagonal rounds),
/// then adds the original state to the result.
pub(crate) fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let initial_state = init_state(key, nonce, counter);
    let mut state = initial_state;

    // 20 rounds (10 iterations of 2 rounds each)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);

        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
    }

    // Serialize to bytes (little-endian)
    let mut output = [0u8; 64];
    for i in 0..16 {
        let bytes = state[i].to_le_bytes();
        output[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }

    output
}

/// Encrypt or decrypt data in-place using ChaCha20 (RFC 8439 Section 2.4)
///
/// XORs each byte of `data` with the keystream generated from
/// `key`, `nonce`, and `initial_counter`.
pub(crate) fn chacha20_crypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    initial_counter: u32,
    data: &mut [u8],
) {
    let mut counter = initial_counter;

    for chunk in data.chunks_mut(64) {
        let keystream = chacha20_block(key, nonce, counter);

        for (byte, ks_byte) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= ks_byte;
        }

        counter = counter.wrapping_add(1);
    }
}

/// HChaCha20 - derives a 256-bit subkey from key and 128-bit nonce (draft-irtf-cfrg-xchacha)
///
/// Used as the first step of XChaCha20 to extend the nonce from 192 to 256 bits.
/// Takes first 16 bytes of the 24-byte xnonce as input.
///
/// Output: words 0-3 and 12-15 of the ChaCha20 state after 20 rounds (no final addition).
pub(crate) fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];

    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (8 words)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }

    // Nonce (4 words) - note: HChaCha20 uses 16-byte nonce, not 12
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    // 20 rounds (10 iterations of 2 rounds each)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);

        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Extract words 0-3 and 12-15 (NOT adding initial state - this is the key difference from chacha20_block)
    let mut output = [0u8; 32];
    for i in 0..4 {
        let bytes = state[i].to_le_bytes();
        output[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    for i in 0..4 {
        let bytes = state[12 + i].to_le_bytes();
        output[16 + i * 4..16 + i * 4 + 4].copy_from_slice(&bytes);
    }

    output
}

/// XChaCha20 encryption/decryption (draft-irtf-cfrg-xchacha)
///
/// Uses 192-bit (24-byte) nonce for better collision resistance.
/// 1. Derive subkey using HChaCha20(key, xnonce[0..16])
/// 2. Construct ChaCha20 nonce as [0,0,0,0] || xnonce[16..24]
/// 3. Run ChaCha20 with subkey and constructed nonce
pub(crate) fn xchacha20_crypt(
    key: &[u8; 32],
    xnonce: &[u8; 24],
    initial_counter: u32,
    data: &mut [u8],
) {
    // Step 1: Derive subkey from first 16 bytes of xnonce
    let subkey = hchacha20(key, xnonce[0..16].try_into().unwrap());

    // Step 2: Construct ChaCha20 nonce: [0, 0, 0, 0] || xnonce[16..24]
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&xnonce[16..24]);

    // Step 3: Run ChaCha20 with derived subkey
    chacha20_crypt(&subkey, &nonce, initial_counter, data);
}
