// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA512 implementation with secure memory handling
//!
//! Implementation per RFC 5869 (HKDF) and RFC 6234 (SHA-512, HMAC).
//! Zero external dependencies. All intermediate values are zeroized.
//!
//! References:
//! - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//!   <https://datatracker.ietf.org/doc/html/rfc5869>
//! - RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
//!   <https://datatracker.ietf.org/doc/html/rfc6234>

#![no_std]
#![warn(missing_docs)]

mod sha512;

use sha512::{sha512, Sha512State};

/// SHA-512 output size in bytes
pub const HASH_LEN: usize = 64;

/// SHA-512 block size in bytes
const BLOCK_LEN: usize = 128;

/// Maximum output length: 255 * 64 = 16320 bytes
pub const MAX_OUTPUT_LEN: usize = 255 * HASH_LEN;

/// HKDF error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Requested output length exceeds maximum (255 * HashLen)
    OutputTooLong,
}

/// HMAC-SHA512 per RFC 6234 Section 8
///
/// Computes HMAC-SHA512(key, message) and writes result to `out`.
/// Zeroizes intermediate state on completion.
fn hmac_sha512(key: &[u8], message: &[u8], out: &mut [u8; HASH_LEN]) {
    let mut k_ipad = [0x36u8; BLOCK_LEN];
    let mut k_opad = [0x5cu8; BLOCK_LEN];

    // If key > BLOCK_LEN, hash it first
    let key_block: [u8; BLOCK_LEN];
    let key_bytes: &[u8] = if key.len() > BLOCK_LEN {
        let mut hashed_key = [0u8; HASH_LEN];
        sha512(key, &mut hashed_key);
        key_block = {
            let mut kb = [0u8; BLOCK_LEN];
            kb[..HASH_LEN].copy_from_slice(&hashed_key);
            // Zeroize hashed_key
            zeroize_64(&mut hashed_key);
            kb
        };
        &key_block[..HASH_LEN]
    } else {
        key
    };

    // XOR key with ipad and opad
    for (i, &kb) in key_bytes.iter().enumerate() {
        k_ipad[i] ^= kb;
        k_opad[i] ^= kb;
    }

    // Inner hash: SHA512(k_ipad || message)
    let mut inner_hash = [0u8; HASH_LEN];
    {
        let mut state = Sha512State::new();
        state.update(&k_ipad);
        state.update(message);
        state.finalize(&mut inner_hash);
    }

    // Outer hash: SHA512(k_opad || inner_hash)
    {
        let mut state = Sha512State::new();
        state.update(&k_opad);
        state.update(&inner_hash);
        state.finalize(out);
    }

    // Zeroize intermediates
    zeroize_128(&mut k_ipad);
    zeroize_128(&mut k_opad);
    zeroize_64(&mut inner_hash);
}

/// HKDF-Extract per RFC 5869 Section 2.2
///
/// PRK = HMAC-Hash(salt, IKM)
/// If salt is empty, uses HASH_LEN zeros as salt.
fn hkdf_extract(salt: &[u8], ikm: &[u8], prk: &mut [u8; HASH_LEN]) {
    let default_salt = [0u8; HASH_LEN];
    let salt = if salt.is_empty() { &default_salt } else { salt };
    hmac_sha512(salt, ikm, prk);
}

/// HKDF-Expand per RFC 5869 Section 2.3
///
/// N = ceil(L/HashLen)
/// T(0) = empty string
/// T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
/// OKM = first L octets of T(1) | T(2) | ... | T(N)
fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let out_len = out.len();
    if out_len > MAX_OUTPUT_LEN {
        return Err(Error::OutputTooLong);
    }
    if out_len == 0 {
        return Ok(());
    }

    let n = (out_len + HASH_LEN - 1) / HASH_LEN; // ceil(L / HashLen)

    let mut t_prev = [0u8; HASH_LEN];
    let mut t_prev_len: usize = 0;
    let mut offset = 0;

    for i in 1..=n {
        // T(i) = HMAC-SHA512(PRK, T(i-1) || info || i)
        let mut t_curr = [0u8; HASH_LEN];

        // Build message: T(i-1) || info || counter
        hmac_sha512_streaming(prk, &t_prev[..t_prev_len], info, i as u8, &mut t_curr);

        // Copy to output
        let copy_len = core::cmp::min(HASH_LEN, out_len - offset);
        out[offset..offset + copy_len].copy_from_slice(&t_curr[..copy_len]);
        offset += copy_len;

        // T(i-1) = T(i) for next iteration
        t_prev = t_curr;
        t_prev_len = HASH_LEN;

        // Zeroize t_curr (now copied to t_prev)
        zeroize_64(&mut t_curr);
    }

    // Zeroize final t_prev
    zeroize_64(&mut t_prev);

    Ok(())
}

/// Streaming HMAC for expand: HMAC(key, t_prev || info || counter)
fn hmac_sha512_streaming(
    key: &[u8; HASH_LEN],
    t_prev: &[u8],
    info: &[u8],
    counter: u8,
    out: &mut [u8; HASH_LEN],
) {
    let mut k_ipad = [0x36u8; BLOCK_LEN];
    let mut k_opad = [0x5cu8; BLOCK_LEN];

    // Key is always HASH_LEN (64 bytes), no need to hash
    for (i, &kb) in key.iter().enumerate() {
        k_ipad[i] ^= kb;
        k_opad[i] ^= kb;
    }

    // Inner hash: SHA512(k_ipad || t_prev || info || counter)
    let mut inner_hash = [0u8; HASH_LEN];
    {
        let mut state = Sha512State::new();
        state.update(&k_ipad);
        state.update(t_prev);
        state.update(info);
        state.update(&[counter]);
        state.finalize(&mut inner_hash);
    }

    // Outer hash: SHA512(k_opad || inner_hash)
    {
        let mut state = Sha512State::new();
        state.update(&k_opad);
        state.update(&inner_hash);
        state.finalize(out);
    }

    // Zeroize
    zeroize_128(&mut k_ipad);
    zeroize_128(&mut k_opad);
    zeroize_64(&mut inner_hash);
}

/// HKDF-SHA512: Extract-then-Expand
///
/// Derives `out.len()` bytes from input keying material.
///
/// # Arguments
/// * `ikm` - Input keying material (secret)
/// * `salt` - Optional salt (can be empty, will use zeros)
/// * `info` - Optional context/application info
/// * `out` - Output buffer for derived key material
///
/// # Errors
/// Returns `Error::OutputTooLong` if `out.len() > 16320` (255 * 64)
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let mut prk = [0u8; HASH_LEN];
    hkdf_extract(salt, ikm, &mut prk);
    let result = hkdf_expand(&prk, info, out);
    zeroize_64(&mut prk);
    result
}

/// Zeroize 64 bytes (SHA-512 output size)
#[inline(always)]
fn zeroize_64(buf: &mut [u8; 64]) {
    unsafe {
        core::ptr::write_volatile(buf, [0u8; 64]);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Zeroize 128 bytes (SHA-512 block size)
#[inline(always)]
fn zeroize_128(buf: &mut [u8; 128]) {
    unsafe {
        core::ptr::write_volatile(buf, [0u8; 128]);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests;
