// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Cryptographically secure random key generation with HKDF derivation.
//!
//! This module provides high-quality key generation by combining OS entropy
//! with hardware-sourced seeds through HKDF-SHA512 derivation.

use redoubt_hkdf::hkdf;
use redoubt_zero::FastZeroizable;

use crate::error::EntropyError;
use crate::u64_seed;

/// Generates a cryptographically secure random key of M bytes.
///
/// The key is derived using a two-stage process:
/// 1. **OS Entropy (IKM)**: M bytes from OS CSPRNG via `getrandom`
/// 2. **Hardware Seeds (Salt)**: 32 bytes from 4×u64 hardware/OS seeds
/// 3. **HKDF-SHA512**: Derives final key = HKDF(ikm=os_entropy, salt=seeds, info=info)
///
/// # Why HKDF derivation?
///
/// The `getrandom` crate provides excellent cryptographic entropy and is the
/// industry standard for random number generation. As an additional layer of
/// protection, we derive keys through HKDF-SHA512 with ephemeral hardware seeds.
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
/// - **For M ≥ 32 bytes**: 256-bit security (limited by salt entropy)
/// - **For M < 32 bytes**: (M × 8)-bit security (limited by key size)
///
/// The double entropy approach ensures:
/// - IKM captures full system entropy state
/// - Salt adds hardware-specific unpredictability
/// - HKDF-SHA512 combines both sources cryptographically
/// - Final key requires multiple components to reconstruct
///
/// # Common Key Sizes
///
/// - `M = 16`: 128-bit keys (AES-128, adequate for most use cases)
/// - `M = 32`: 256-bit keys (XChaCha20, maximum practical security)
/// - `M = 64`: 512-bit keys (HMAC-SHA512, capped at 256-bit effective security)
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
pub fn generate_random_key<const M: usize>(
    info: &[u8],
    output_key: &mut [u8; M],
) -> Result<(), EntropyError> {
    // 1. Generate M bytes of OS entropy (IKM)
    let mut ikm = [0u8; M];
    getrandom::fill(&mut ikm).map_err(|_| EntropyError::EntropyNotAvailable)?;

    // 2. Generate 32 bytes of hardware/OS seed entropy (Salt)
    let mut salt = [0u8; 32];
    for i in 0..4 {
        let mut seed = 0u64;

        unsafe { u64_seed::generate(&mut seed as *mut u64)? };
        salt[i * 8..(i + 1) * 8].copy_from_slice(&seed.to_le_bytes());

        seed.fast_zeroize();
    }

    // 3. Derive final key via HKDF-SHA512 directly to output
    hkdf(&ikm, &salt, info, output_key).map_err(|_| EntropyError::EntropyNotAvailable)?;

    // 4. Zeroize intermediates
    ikm.fast_zeroize();
    salt.fast_zeroize();

    Ok(())
}
