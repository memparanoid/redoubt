// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Type aliases for CipherBox internals.

use alloc::vec::Vec;

/// One field, sealed: the form the box keeps between opens, and the only one
/// that outlives a call.
pub type Ciphertext = Vec<u8>;

/// A buffer the AEAD works over in place, so what goes in is not what comes
/// out: a ciphertext arrives, a plaintext is there when the call returns, and
/// the decoder that reads it leaves zeros behind.
pub type Data = Vec<u8>;

/// A single nonce used for AEAD encryption.
pub type Nonce = Vec<u8>;

/// A single authentication tag from AEAD encryption.
pub type Tag = Vec<u8>;

/// One [`Ciphertext`] per encrypted field.
pub type Ciphertexts<const N: usize> = [Ciphertext; N];

/// One [`Data`] buffer per encrypted field.
pub type DataBuffers<const N: usize> = [Data; N];

/// Array of nonces for N encrypted fields.
pub type Nonces<const N: usize> = [Nonce; N];

/// Array of authentication tags for N encrypted fields.
pub type Tags<const N: usize> = [Tag; N];
