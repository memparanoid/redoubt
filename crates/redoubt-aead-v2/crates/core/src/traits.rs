// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What an AEAD can be asked, in the widths it actually takes.
//!
//! A key here is `&[u8; 32]` or `&[u8; 16]` and never `&[u8]`. A backend that
//! took a slice would have to narrow it and answer for the day it did not fit,
//! and every backend would answer the same three times over; with the width in
//! the type, what does not fit does not compile. The one narrowing that is
//! still owed belongs wherever a caller's slice meets an array, which is the
//! one place that dispatches on what the machine turned out to have.
//!
//! So [`AeadEncrypt::encrypt`] returns nothing, and [`AeadDecrypt::decrypt`]
//! returns only the failure that is about the bytes rather than their shape.
//!
//! Sealing and opening are two traits so that a caller can be given one and
//! not the other. [`AeadBackend`] is both.

use crate::AeadError;

/// The three widths an AEAD works in.
///
/// Their own trait, so that a bound naming both halves does not have to say
/// that the key of one is the key of the other.
pub trait AeadSizes {
    /// The key, as wide as this AEAD takes.
    type Key;
    /// The nonce, as wide as this AEAD takes.
    type Nonce;
    /// The tag, as wide as this AEAD writes.
    type Tag;
}

/// Sealing, in place.
pub trait AeadEncrypt: AeadSizes {
    /// `data` becomes its ciphertext, and `tag` the proof that it did.
    fn encrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    );
}

/// Opening, in place.
pub trait AeadDecrypt: AeadSizes {
    /// `data` becomes its plaintext, and only if `tag` says it is the one that
    /// was sealed.
    ///
    /// An implementation empties `data` before returning: what is in the
    /// buffer at that moment is a keystream laid over bytes nobody
    /// authenticated, and a caller that reads it reads what an attacker chose
    /// to send.
    ///
    /// # Errors
    ///
    /// [`AeadError::AuthenticationFailed`], and only that: the widths are
    /// settled by the types.
    fn decrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), AeadError>;
}

/// A sealing and an opening, and the nonce to ask for one.
pub trait AeadBackend: AeadEncrypt + AeadDecrypt {
    /// A nonce this backend has not given before, into `out`.
    ///
    /// # Errors
    ///
    /// [`AeadError::EntropyNotAvailable`], where the machine has no
    /// randomness to give.
    fn generate_nonce(&mut self, out: &mut Self::Nonce) -> Result<(), AeadError>;
}
