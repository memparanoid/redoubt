// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Cryptographically secure random key generation with HKDF derivation.
//!
//! OS entropy through HKDF-SHA256, so that a caller's `info` separates one key
//! from another.

extern crate alloc;
use alloc::vec;

use redoubt_hkdf::hkdf;
use redoubt_zero::ZeroizingGuard;

use crate::error::EntropyError;

/// What separates this extraction from every other use of the same hash.
///
/// Fixed and in the clear, which is what a salt is: RFC 5869 §3.1 says a salt
/// is "non-secret" and "can be re-used", and gives this exact case — a
/// generator applying HKDF to a pool of entropy "can fix a salt value and use
/// it for multiple applications of HKDF without having to protect the secrecy
/// of the salt".
///
/// What it replaced was a salt drawn per call from the same syscall as the
/// keying material below. A salt buys independence between uses of the hash,
/// and one taken from the source it is meant to be independent of buys none —
/// at eight more trips into the kernel for a thirty-two byte key.
const SALT: &[u8] = b"redoubt-rand.generate_random_key.v1";

/// Generates a cryptographically secure random key.
///
/// `HKDF(ikm = getrandom(key_len), salt = SALT, info = info)`.
///
/// # Why HKDF at all
///
/// For `info`, and for nothing else. The keying material is already a uniformly
/// random string, so the derivation adds no entropy to it — RFC 5869 §3.3 says
/// as much, that extraction may be skipped outright when the material is
/// already a strong key. What the same section says not to skip is the expand
/// step, "especially because it would omit the use of 'info'".
///
/// So what a caller gets is domain separation: two keys asked for under
/// different `info` are unrelated, and a key asked for twice under the same one
/// is still two different keys, because the material below is drawn fresh.
///
/// # Security Level
///
/// `key_len × 8` bits, up to the 256 of the hash. Nothing here adds to what the
/// operating system's generator gave.
///
/// # Common Key Sizes
///
/// - `16`: 128-bit keys (AES-128, adequate for most use cases)
/// - `32`: 256-bit keys (XChaCha20, maximum practical security)
/// - `64`: 512-bit keys (HMAC-SHA512, capped at 256-bit effective security)
///
/// # Arguments
///
/// * `info` - Context string for domain separation (e.g., `b"redoubt.master_key.v1"`)
/// * `output_key` - Output buffer for the generated key
///
/// # Errors
///
/// Returns `EntropyError::EntropyNotAvailable` if:
/// - OS entropy source fails (getrandom)
/// - Output key is empty
///
/// # Example
///
/// ```rust
/// use redoubt_rand::generate_random_key;
///
/// // Generate 32-byte XChaCha20 key
/// let mut key = [0u8; 32];
/// generate_random_key(b"my_app.encryption_key.v1", &mut key)
///     .expect("Failed to generate key");
///
/// // Generate 16-byte AES-128 key
/// let mut aes_key = [0u8; 16];
/// generate_random_key(b"my_app.aes_key.v1", &mut aes_key)
///     .expect("Failed to generate key");
/// ```
pub fn generate_random_key(info: &[u8], output_key: &mut [u8]) -> Result<(), EntropyError> {
    let mut ikm = ZeroizingGuard::from_mut(&mut vec![0u8; output_key.len()]);

    getrandom::fill(&mut ikm).map_err(|_| EntropyError::EntropyNotAvailable)?;

    hkdf(&ikm, SALT, info, output_key).map_err(|_| EntropyError::EntropyNotAvailable)
}
