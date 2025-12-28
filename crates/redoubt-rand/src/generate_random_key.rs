// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Cryptographically secure random key generation with HKDF derivation.
//!
//! This module provides high-quality key generation by combining OS entropy
//! with hardware-sourced seeds through HKDF-SHA512 derivation.

extern crate alloc;
use alloc::vec;

use redoubt_hkdf::hkdf;
use redoubt_zero::ZeroizingGuard;

use crate::error::EntropyError;
use crate::u64_seed;

/// Generates a cryptographically secure random key.
///
/// The key is derived using a two-stage process:
/// 1. **OS Entropy (IKM)**: Same size as output key from OS CSPRNG via `getrandom`
/// 2. **Hardware Seeds (Salt)**: Next multiple of 64 bytes from hardware/OS seeds
/// 3. **HKDF-SHA256**: Derives final key = HKDF(ikm=os_entropy, salt=seeds, info=info)
///
/// # Why HKDF derivation?
///
/// The `getrandom` crate provides excellent cryptographic entropy and is the
/// industry standard for random number generation. As an additional layer of
/// protection, we derive keys through HKDF-SHA256 with ephemeral hardware seeds.
///
/// This approach provides defense-in-depth: if sensitive key material were to
/// leak during generation (e.g., through compiler spills, unexpected memory dumps,
/// or side-channel attacks), an attacker would need both the IKM and the ephemeral
/// seeds to reconstruct the final key. Since seeds are generated on-demand from
/// hardware sources and immediately zeroized, this significantly reduces the
/// attack surface.
///
/// # Security Level
///
/// - **For key_len ≥ 32 bytes**: 256-bit security (limited by salt entropy)
/// - **For key_len < 32 bytes**: (key_len × 8)-bit security (limited by key size)
///
/// The double entropy approach ensures:
/// - IKM captures full system entropy state
/// - Salt adds hardware-specific unpredictability
/// - HKDF-SHA256 combines both sources cryptographically
/// - Final key requires multiple components to reconstruct
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
/// - Hardware seed generation fails
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
    let key_len = output_key.len();

    // 1. Generate key_len bytes of OS entropy (IKM)
    let mut ikm = ZeroizingGuard::from_mut(&mut vec![0u8; key_len]);
    getrandom::fill(&mut ikm).map_err(|_| EntropyError::EntropyNotAvailable)?;

    // 2. Generate hardware/OS seed entropy (Salt)
    // Salt size: next multiple of 64 bytes = 8 u64s per 64 bytes
    let salt_len_u64 = key_len.div_ceil(64) * 8;
    let mut salt = ZeroizingGuard::from_mut(&mut vec![0u64; salt_len_u64]);
    // Generate u64 seeds directly into salt Vec (guaranteed 8-byte alignment)
    for i in 0..salt_len_u64 {
        unsafe {
            let seed_ptr = salt.as_mut_ptr().add(i);
            u64_seed::generate(seed_ptr)?;
        }
    }

    // 3. Derive final key via HKDF-SHA256 directly to output
    // Convert salt to byte slice for HKDF
    let salt_bytes = unsafe {
        core::slice::from_raw_parts(salt.as_ptr() as *const u8, salt_len_u64 * 8)
    };
    hkdf(&ikm, salt_bytes, info, output_key).map_err(|_| EntropyError::EntropyNotAvailable)
}
