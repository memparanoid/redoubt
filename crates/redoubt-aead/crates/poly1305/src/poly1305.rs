// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The authenticator: what it holds, and the order things are done to it.
//!
//! Storage and sequence, and nothing else. Rust owns the key and empties it
//! when it dies; every byte of the message that is read and every limb that is
//! multiplied or carried belongs to the backend, the buffering included —
//! deciding where a block ends means reading the message.
//!
//! Nothing here is `Copy` or `Clone`: a copy is a second place the key sits,
//! with nobody able to name one of the two.

#[cfg(test)]
use redoubt_zero::ZeroizeOnDropSentinel;
use redoubt_zero::{FastZeroizable, RedoubtZero};

use redoubt_aead_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};
use redoubt_asm::Backend;

use crate::backend::{finalize, init, update};
use crate::consts::LIMBS;

/// A one-time authenticator over 2^130 - 5.
///
/// One key, one message. The key is a pair — `r`, which the message is
/// evaluated at, and `s`, which is added to the result — and a second message
/// under the same pair gives away the first, so nothing here takes a second
/// one.
///
/// Asking twice is not refused, it is emptied — [`Self::finalize_mut`] wipes
/// what it answered from, so a second call answers from nothing. Holding the
/// caller to one tag is the caller's job, and in this workspace the caller is
/// the AEAD.
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct Poly1305 {
    /// What the message is evaluated at, clamped and spread over five limbs.
    r: [u32; LIMBS],
    /// The pad added at the end, kept as it arrived.
    s: [u8; BLOCK_SIZE],
    /// The polynomial so far.
    acc: [u64; LIMBS],
    /// What has arrived since the last whole block.
    block: [u8; BLOCK_SIZE],
    /// How much of `block` is that.
    filled: usize,
    /// Runtime verification that zeroization happened, for the tests that read
    /// it.
    ///
    /// Gated because it is an `Arc<AtomicBool>` — one heap allocation per
    /// value, in a type whose whole reason for existing is to leave nothing in
    /// memory.
    #[cfg(test)]
    __sentinel: ZeroizeOnDropSentinel,
}

impl Poly1305 {
    /// One with no key yet, which [`Self::init`] is what gives it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Splits `key` into the pair the message is authenticated under.
    ///
    /// Takes `&mut self` and hands nothing back. A value returned by move is a
    /// copy the compiler places where it likes and empties nowhere, and what
    /// would leave here is the clamped pair.
    pub fn init(&mut self, backend: Backend, key: &[u8; KEY_SIZE]) {
        init(backend, &mut self.r, &mut self.s, key);
    }

    /// As much of the message as the caller has. Any number of calls says the
    /// same as one call with all of it.
    pub fn update(&mut self, backend: Backend, said: &[u8]) {
        update(
            backend,
            &mut self.acc,
            &self.r,
            &mut self.block,
            &mut self.filled,
            said,
        );
    }

    /// The same, and then zeros up to the next block boundary.
    ///
    /// What an AEAD counts its associated data and its ciphertext with, so
    /// that neither can be read as part of the other.
    pub fn update_padded(&mut self, backend: Backend, said: &[u8]) {
        self.update(backend, said);

        let owed = (BLOCK_SIZE - (said.len() % BLOCK_SIZE)) % BLOCK_SIZE;

        if owed > 0 {
            self.update(backend, &[0u8; BLOCK_SIZE][..owed]);
        }
    }

    /// The tag, and nothing of the message left behind.
    ///
    /// Takes a pointer and not the value. A parameter taken by value is an
    /// instruction to copy: the caller holds one of these in a slot of its own
    /// frame, and handing it over duplicates it. A drop at the end would then
    /// empty the copy it was given, while the slot it was copied from is a
    /// value nobody owns any more — so nothing drops it, and the last block of
    /// the message stays there until the frame is reused.
    ///
    /// There is one of this one, and the wipe below is what that drop would
    /// have done, on the only copy there is.
    ///
    /// What it cannot do is refuse a second call. The emptied state is what
    /// that call would answer for.
    pub fn finalize_mut(&mut self, backend: Backend, out: &mut [u8; TAG_SIZE]) {
        finalize(
            backend,
            &mut self.acc,
            &self.r,
            &self.s,
            &self.block[..self.filled],
            out,
        );

        self.fast_zeroize();
    }

    /// Something in it that a zeroization has to remove.
    #[cfg(test)]
    pub(crate) fn unzeroize(&mut self) {
        self.r = [1, 2, 3, 4, 5];
    }
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Poly1305 {{ [protected] }}")
    }
}

/// The tag of one message, for a caller that has all of it.
///
/// The message does not go through [`Poly1305::update`]: a caller that has the
/// whole of it has nothing to buffer, and handing it over in one piece is what
/// lets it go through every block of itself without the bytes coming back here
/// in between.
pub fn tag(backend: Backend, key: &[u8; KEY_SIZE], said: &[u8], out: &mut [u8; TAG_SIZE]) {
    let mut poly = Poly1305::new();

    poly.init(backend, key);

    finalize(backend, &mut poly.acc, &poly.r, &poly.s, said, out);
}
