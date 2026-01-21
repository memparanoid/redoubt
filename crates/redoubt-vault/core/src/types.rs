// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Type aliases for CipherBox internals.

use alloc::vec::Vec;

/// A single ciphertext (encrypted field data).
pub type Ciphertext = Vec<u8>;

/// A single nonce used for AEAD encryption.
pub type Nonce = Vec<u8>;

/// A single authentication tag from AEAD encryption.
pub type Tag = Vec<u8>;

/// Array of ciphertexts for N encrypted fields.
pub type Ciphertexts<const N: usize> = [Ciphertext; N];

/// Array of nonces for N encrypted fields.
pub type Nonces<const N: usize> = [Nonce; N];

/// Array of authentication tags for N encrypted fields.
pub type Tags<const N: usize> = [Tag; N];
