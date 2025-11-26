// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! XChaCha20-Poly1305 AEAD implementation (RFC 8439 + draft-irtf-cfrg-xchacha)
//!
//! Provides authenticated encryption with associated data using:
//! - XChaCha20 for encryption (192-bit nonce)
//! - Poly1305 for authentication

use memalloc::AllockedVec;
use poly1305::{
    Key as Poly1305Key, Poly1305,
    universal_hash::{KeyInit, UniversalHash},
};
use zeroize::Zeroize;

use crate::chacha20::{chacha20_block, hchacha20, xchacha20_crypt};
use crate::sensitive::SensitiveArrayU8;

/// Authentication tag size in bytes
pub const TAG_SIZE: usize = 16;

/// Key size in bytes
pub const KEY_SIZE: usize = 32;

/// Nonce size in bytes (extended nonce for XChaCha20)
pub const NONCE_SIZE: usize = 24;

/// Errors that can occur during AEAD decryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecryptError {
    /// Invalid nonce size (must be exactly NONCE_SIZE bytes)
    #[cfg(test)]
    #[error("invalid nonce size: expected {NONCE_SIZE} bytes")]
    InvalidNonceSize,

    /// Ciphertext is too short (must be at least TAG_SIZE bytes)
    #[error("ciphertext too short: expected at least {TAG_SIZE} bytes")]
    CiphertextTooShort,

    /// Authentication tag verification failed (ciphertext or AAD was modified)
    #[error("authentication failed: tag mismatch")]
    AuthenticationFailed,
}

/// Generate Poly1305 one-time key from XChaCha20 keystream (counter=0)
fn generate_poly_key(key: &[u8; 32], xnonce: &[u8; 24], poly_key: &mut [u8; 32]) {
    // Derive subkey using HChaCha20
    let mut subkey = SensitiveArrayU8::<32>::new();
    hchacha20(key, xnonce[0..16].try_into().unwrap(), &mut subkey);

    // Construct ChaCha20 nonce: [0,0,0,0] || xnonce[16..24]
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&xnonce[16..24]);

    // Generate keystream block with counter=0
    let mut block = SensitiveArrayU8::<64>::new();
    chacha20_block(&subkey, &nonce, 0, &mut block);

    // First 32 bytes are the Poly1305 key
    poly_key.copy_from_slice(&block[0..32]);

    subkey.zeroize();
    block.zeroize();
}

/// Compute Poly1305 tag over AAD and ciphertext (RFC 8439 Section 2.8)
///
/// MAC input format:
/// - aad || pad16(aad)
/// - ciphertext || pad16(ciphertext)
/// - len(aad) as u64 little-endian
/// - len(ciphertext) as u64 little-endian
fn compute_tag(poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8], output: &mut [u8; 16]) {
    let key = Poly1305Key::from(*poly_key);
    let mut mac = Poly1305::new(&key);

    // AAD with padding
    mac.update_padded(aad);

    // Ciphertext with padding
    mac.update_padded(ciphertext);

    // Lengths as u64 little-endian
    let mut len_block = SensitiveArrayU8::<16>::new();
    len_block[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    mac.update_padded(len_block.as_slice());

    let mut tag = mac.finalize();
    len_block.zeroize();

    let tag_bytes = tag.as_mut_slice();

    for (i, b) in tag_bytes.iter_mut().enumerate() {
        output[i] = core::mem::take(b);
    }

    debug_assert!(tag_bytes.iter().all(|b| *b == 0));
}

/// Encrypt plaintext with XChaCha20-Poly1305 AEAD
///
/// # Arguments
/// - `key`: 32-byte encryption key
/// - `xnonce`: 24-byte nonce (must be unique per message)
/// - `aad`: Additional authenticated data (not encrypted, but authenticated)
/// - `plaintext`: Mutable buffer — encrypted in-place and drained, which is therefore zeroized
///
/// # Returns
/// `AllockedVec<u8>` containing ciphertext with 16-byte authentication tag appended
///
/// # Security
/// - Output buffer uses `AllockedVec` (no reallocation, zeroized on drop)
pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    xnonce: &[u8; 24],
    aad: &[u8],
    plaintext: &mut [u8],
) -> AllockedVec<u8> {
    // Encrypt in-place (counter starts at 1)
    xchacha20_crypt(key, xnonce, 1, plaintext);
    let ciphertext = plaintext; // plaintext is now encrypted

    // Generate Poly1305 one-time key
    let mut poly_key = SensitiveArrayU8::<32>::new();
    generate_poly_key(key, xnonce, &mut poly_key);

    // Compute authentication tag
    let mut tag = SensitiveArrayU8::<16>::new();
    compute_tag(&poly_key, aad, ciphertext, &mut tag);

    // Create output buffer and drain ciphertext + tag
    let mut output = AllockedVec::with_capacity(ciphertext.len() + TAG_SIZE);
    output
        .drain_from(ciphertext)
        .expect("infallible: capacity = ciphertext.len() + TAG_SIZE");
    output
        .drain_from(tag.as_mut_slice())
        .expect("infallible: TAG_SIZE bytes remaining");

    poly_key.zeroize();
    tag.zeroize();

    output
}

/// Decrypt ciphertext with XChaCha20-Poly1305 AEAD
///
/// # Arguments
/// - `key`: 32-byte encryption key
/// - `xnonce`: 24-byte nonce (same as used for encryption)
/// - `aad`: Additional authenticated data (same as used for encryption)
/// - `ciphertext_with_tag`: Mutable buffer — decrypted in-place and drained, which is therefore zeroized
///
/// # Returns
/// - `Ok(AllockedVec<u8>)` containing plaintext if authentication succeeds
/// - `Err(DecryptError)` if authentication fails (input buffer is zeroized)
///
/// # Security
/// - On authentication failure, input buffer is zeroized before returning error
/// - Output buffer uses `AllockedVec` (no reallocation, zeroized on drop)
pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    xnonce: &[u8; 24],
    aad: &[u8],
    ciphertext_with_tag: &mut [u8],
) -> Result<AllockedVec<u8>, DecryptError> {
    // Must have at least TAG_SIZE bytes
    if ciphertext_with_tag.len() < TAG_SIZE {
        ciphertext_with_tag.zeroize();
        return Err(DecryptError::CiphertextTooShort);
    }

    // Split ciphertext and tag
    let (ciphertext, received_tag) =
        ciphertext_with_tag.split_at_mut(ciphertext_with_tag.len() - TAG_SIZE);

    // Generate Poly1305 one-time key
    let mut poly_key = SensitiveArrayU8::<32>::new();
    generate_poly_key(key, xnonce, &mut poly_key);

    // Compute expected tag
    let mut expected_tag = SensitiveArrayU8::<16>::new();
    compute_tag(&poly_key, aad, ciphertext, &mut expected_tag);

    // Constant-time comparison to prevent timing attacks
    if !constant_time_eq(expected_tag.as_slice(), received_tag) {
        ciphertext.zeroize();
        received_tag.zeroize();
        poly_key.zeroize();
        expected_tag.zeroize();
        return Err(DecryptError::AuthenticationFailed);
    }

    // Authentication passed, decrypt in-place
    xchacha20_crypt(key, xnonce, 1, ciphertext);
    let plaintext = ciphertext; // ciphertext is now decrypted

    // Create output buffer and drain plaintext
    let mut output = AllockedVec::with_capacity(plaintext.len());
    output
        .drain_from(plaintext)
        .expect("infallible: capacity = plaintext.len()");

    // Zeroize tag and sensitive intermediates
    received_tag.zeroize();
    poly_key.zeroize();
    expected_tag.zeroize();

    Ok(output)
}

/// Decrypt ciphertext with XChaCha20-Poly1305 AEAD (slice version for testing)
///
/// Same as `xchacha20poly1305_decrypt` but accepts slices instead of fixed-size arrays.
/// Returns `InvalidNonceSize` if nonce is not exactly 24 bytes.
#[cfg(test)]
pub(crate) fn xchacha20poly1305_decrypt_slice(
    key: &[u8],
    xnonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &mut [u8],
) -> Result<AllockedVec<u8>, DecryptError> {
    let key: &[u8; 32] = key.try_into().map_err(|_| DecryptError::InvalidNonceSize)?;
    let xnonce: &[u8; 24] = xnonce
        .try_into()
        .map_err(|_| DecryptError::InvalidNonceSize)?;
    xchacha20poly1305_decrypt(key, xnonce, aad, ciphertext_with_tag)
}

/// Constant-time comparison of two byte slices
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
