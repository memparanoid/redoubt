// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The construction: which primitive is asked what, and in what order.
//!
//! Nothing is computed here. Every byte of key, keystream and tag belongs to
//! one of the two crates below; what this file owns is the one-time key
//! between them, and the order — which is the part the construction is.

use redoubt_aead_core::consts::chacha::{KEY_SIZE, XNONCE_SIZE};
use redoubt_aead_core::consts::poly1305::{KEY_SIZE as POLY_KEY_SIZE, TAG_SIZE};
use redoubt_aead_core::{AeadCoreError, AeadDecrypt, AeadEncrypt, AeadSizes, constant_time_eq};
use redoubt_alloc::RedoubtArray;
use redoubt_asm::Backend;
use redoubt_chacha::xchacha20::XChaCha20;
use redoubt_mem::copy_nonoverlapping;
use redoubt_poly1305::Poly1305;
use redoubt_zero::RedoubtZero;
use redoubt_zero::{FastZeroizable, ZeroizingGuard};

/// The counter the one-time key is taken from, and the one the message starts
/// at.
///
/// Thirty-two bytes of the first block are the authenticator's key and the
/// other thirty-two are discarded — not reused for the message, which would
/// hand an attacker who learns the key the first half of the keystream.
const POLY_KEY_COUNTER: u32 = 0;
const MESSAGE_COUNTER: u32 = 1;

/// The block the tag ends on: two lengths, eight bytes each.
const LENGTHS_SIZE: usize = 2 * core::mem::size_of::<u64>();

type OneTimeKey = ZeroizingGuard<RedoubtArray<u8, POLY_KEY_SIZE>>;

/// XChaCha20 for the message, Poly1305 for the proof it was not touched.
///
/// It holds nothing but where its operations go: the key arrives at each call
/// and leaves with it. What is derived from that key — the subkey, the
/// one-time authenticator key — lives no longer than the call that made it.
///
/// # Panics
///
/// Where one `data` would take the counter underneath past its end. The
/// keystream is RFC 8439's with a counter of thirty-two bits and the message
/// starts at one, so that is a single slice of more than 2^38 - 64 bytes —
/// around two hundred and fifty-six gibibytes, contiguous and in memory. It
/// stops rather than lay the first block's keystream over the one after the
/// last, which is the one thing a stream cipher cannot survive.
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct XChaCha20Poly1305 {
    cipher: XChaCha20,
    #[cfg(test)]
    #[fast_zeroize(skip)]
    backend: Backend,
    #[cfg(test)]
    __sentinel: redoubt_zero::ZeroizeOnDropSentinel,
}

impl XChaCha20Poly1305 {
    /// One whose operations go where the target says.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cipher: XChaCha20::new(),
            #[cfg(test)]
            backend: Backend::default(),
            #[cfg(test)]
            __sentinel: redoubt_zero::ZeroizeOnDropSentinel::default(),
        }
    }

    /// One that sends its operations where it is told, both halves of it.
    ///
    /// Gated, and the only way a backend other than the target's gets in here:
    /// a test that wants the whole chain in Rust has to say so to the cipher
    /// and to the authenticator, and without this there is nothing to say it
    /// with.
    #[cfg(test)]
    #[must_use]
    pub fn with_backend(backend: Backend) -> Self {
        let mut made = Self::new();

        made.backend = backend;

        made
    }

    /// Where the authenticator's operations go: the one a test of this crate
    /// named, and the target's everywhere else.
    fn backend(&self) -> Backend {
        #[cfg(test)]
        {
            self.backend
        }

        #[cfg(not(test))]
        {
            Backend::default()
        }
    }

    /// The first thirty-two bytes of the keystream, which is what authenticates
    /// this message and nothing else.
    ///
    /// The caller empties it. It is the one secret this file holds rather than
    /// hands straight to a primitive, and it outlives neither call it sits
    /// between.
    fn one_time_key(&self, key: &[u8; KEY_SIZE], nonce: &[u8; XNONCE_SIZE], out: &mut OneTimeKey) {
        self.cipher.xor(key, nonce, POLY_KEY_COUNTER, out);
    }

    /// The tag over the associated data and the ciphertext, in that order.
    ///
    /// Each of the two is padded to a block boundary and the lengths of both
    /// are written at the end, so that moving a byte from one into the other
    /// cannot leave the tag unchanged. That is what `update_padded` is for, and
    /// the trailing sixteen bytes are the two lengths as they are counted.
    fn tag(
        &self,
        one_time_key: &OneTimeKey,
        aad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8; TAG_SIZE],
    ) {
        let mut authenticator = Poly1305::new();

        authenticator.init(self.backend(), one_time_key.as_array());

        self.tag_with(&mut authenticator, aad, ciphertext);

        authenticator.finalize_mut(self.backend(), out);
    }

    /// Everything the authenticator is told, and none of what it answers.
    ///
    /// It stops before the tag on purpose. What is left in an authenticator
    /// that was told everything and asked nothing is exactly what
    /// `finalize_mut` has to remove — and the only way to photograph that is
    /// for somebody else to still own the authenticator at that moment, which
    /// is what taking it by reference allows and what `forensics` does.
    pub(crate) fn tag_with(&self, authenticator: &mut Poly1305, aad: &[u8], ciphertext: &[u8]) {
        authenticator.update_padded(self.backend(), aad);
        authenticator.update_padded(self.backend(), ciphertext);

        // Nothing here is emptied, and that is not an oversight. Both are
        // lengths: an attacker who saw the message knows how long its
        // associated data was and how long its ciphertext is. And `to_le_bytes`
        // has already made a copy nothing can name, so a wipe of the two below
        // would leave the machine exactly as dirty while reading as though it
        // had not.
        let said = (aad.len() as u64).to_le_bytes();
        let sealed = (ciphertext.len() as u64).to_le_bytes();
        let mut lengths = [0u8; LENGTHS_SIZE];

        // SAFETY: each source is one word and `lengths` is two, so both writes
        // land inside it; and the three are separate locals, so no pair of them
        // overlaps.
        unsafe {
            copy_nonoverlapping(said.as_ptr(), lengths.as_mut_ptr(), said.len());
            copy_nonoverlapping(
                sealed.as_ptr(),
                lengths.as_mut_ptr().add(said.len()),
                sealed.len(),
            );
        }

        authenticator.update(self.backend(), &lengths);
    }

    /// Something in it that a zeroization has to remove.
    #[cfg(test)]
    pub(crate) fn unzeroize(&mut self) {
        self.cipher.unzeroize();
    }
}

impl AeadSizes for XChaCha20Poly1305 {
    type Key = [u8; KEY_SIZE];
    type Nonce = [u8; XNONCE_SIZE];
    type Tag = [u8; TAG_SIZE];
}

impl AeadEncrypt for XChaCha20Poly1305 {
    fn encrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    ) {
        let mut one_time_key = OneTimeKey::from_default();
        self.one_time_key(key, nonce, &mut one_time_key);

        // The message is enciphered before it is authenticated, because what
        // is authenticated is the ciphertext.
        self.cipher.xor(key, nonce, MESSAGE_COUNTER, data);
        self.tag(&one_time_key, aad, data, tag);

        one_time_key.fast_zeroize();
    }
}

impl AeadDecrypt for XChaCha20Poly1305 {
    fn decrypt(
        &mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), AeadCoreError> {
        let mut one_time_key = OneTimeKey::from_default();
        self.one_time_key(key, nonce, &mut one_time_key);

        let mut expected = [0u8; TAG_SIZE];

        self.tag(&one_time_key, aad, data, &mut expected);

        let same = constant_time_eq(&expected, tag);

        one_time_key.fast_zeroize();
        expected.fast_zeroize();

        if !same {
            // What is in the buffer is what an attacker sent, and a caller
            // that reads it reads that. Nothing here has deciphered it and
            // nothing will.
            data.fast_zeroize();

            return Err(AeadCoreError::AuthenticationFailed);
        }

        self.cipher.xor(key, nonce, MESSAGE_COUNTER, data);

        Ok(())
    }
}
