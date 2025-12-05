// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::error::EntropyError;

/// Trait for cryptographically secure random number generators.
///
/// Implementations must provide randomness suitable for cryptographic operations
/// (e.g., key generation, nonce creation). Typically backed by OS-level CSPRNGs.
pub trait EntropySource {
    /// Fills the destination buffer with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError::EntropyNotAvailable`] if the system entropy source
    /// is unavailable or fails to generate random data.
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError>;
}

/// Trait for XChaCha20 nonce generators (192-bit nonces).
///
/// Implementations generate unique nonces suitable for AEAD encryption with
/// XChaCha20-Poly1305. Each nonce must be unique per encryption operation with
/// the same key to maintain security guarantees.
pub trait NonceGenerator<const N: usize> {
    /// Fills the buffer with a unique 192-bit (24-byte) nonce.
    ///
    /// # Expected buffer size
    ///
    /// The buffer should be exactly 24 bytes. Implementations may panic or return
    /// an error if the buffer size is incorrect.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError::EntropyNotAvailable`] if the underlying entropy
    /// source fails to provide random data.
    fn generate_nonce(&mut self) -> Result<[u8; N], EntropyError>;
}
