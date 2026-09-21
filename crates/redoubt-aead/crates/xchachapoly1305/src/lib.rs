// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! XChaCha20-Poly1305, the AEAD of draft-irtf-cfrg-xchacha.
//!
//! A stream cipher and a one-time authenticator standing together: the first
//! sixteen bytes of the nonce derive a subkey, the first thirty-two bytes of
//! that subkey's keystream are the authenticator's one-time key, and the
//! message is enciphered from the block after it.
//!
//! The nonce is twenty-four bytes, which is long enough to pick at random
//! rather than count — and that is the whole reason this exists rather than
//! ChaCha20-Poly1305. Picking one is not done here: what generates a nonce has
//! to know where randomness comes from, and nothing at this layer does.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod forensics;

mod xchachapoly1305;

pub use xchachapoly1305::XChaCha20Poly1305;
