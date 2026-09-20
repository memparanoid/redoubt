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
/// under the same pair gives away the first. Which is why the key arrives at
/// construction: nothing here takes a second one.
///
/// Asking twice is not refused, it is emptied — [`Self::finalize_mut`] wipes
/// what it answered from, so a second call answers from nothing. Holding the
/// caller to one tag is the caller's job, and in this workspace the caller is
/// the AEAD.
#[derive(Default, RedoubtZero)]
#[fast_zeroize(drop)]
pub struct Poly1305 {
    /// Which of the two backends this one's operations go to.
    #[fast_zeroize(skip)]
    backend: Backend,
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
    /// One that will authenticate one message under `key`.
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let mut poly = Self {
            backend: Backend::default(),
            r: [0; LIMBS],
            s: [0; BLOCK_SIZE],
            acc: [0; LIMBS],
            block: [0; BLOCK_SIZE],
            filled: 0,
            #[cfg(test)]
            __sentinel: ZeroizeOnDropSentinel::default(),
        };

        init(Backend::default(), &mut poly.r, &mut poly.s, key);

        poly
    }

    /// As much of the message as the caller has. Any number of calls says the
    /// same as one call with all of it.
    pub fn update(&mut self, said: &[u8]) {
        update(
            self.backend,
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
    pub fn update_padded(&mut self, said: &[u8]) {
        self.update(said);

        let owed = (BLOCK_SIZE - (said.len() % BLOCK_SIZE)) % BLOCK_SIZE;

        if owed > 0 {
            self.update(&[0u8; BLOCK_SIZE][..owed]);
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
    pub fn finalize_mut(&mut self, out: &mut [u8; TAG_SIZE]) {
        finalize(
            self.backend,
            &mut self.acc,
            &self.r,
            &self.s,
            &self.block[..self.filled],
            out,
        );

        self.fast_zeroize();
    }

    /// Where the operations after this one go.
    ///
    /// Gated, and reachable from above only with `test-utils`: an AEAD is a
    /// cipher and an authenticator standing together, and a test that wants
    /// the whole of it in Rust has to be able to say so to both. Nothing that
    /// ships asks — what ships takes the assembly where the target has it.
    ///
    /// The clamp is not one of the operations after this one. It ran when the
    /// key arrived, on whatever [`Self::new`] was given, and it is the same
    /// answer either way — a caller that needs it named too wants
    /// [`tag_with_backend`], which has the key and the choice at once.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_backend(&mut self, backend: Backend) {
        self.backend = backend;
    }

    /// The same, for a caller that has one to hand rather than one to keep.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_backend(mut self, backend: Backend) -> Self {
        self.set_backend(backend);

        self
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

/// The tag of one message, with the backend named.
///
/// It does not go through [`Poly1305`]: a caller that has the whole message
/// has nothing to buffer, and handing it over in one piece is what lets it go
/// through every block of itself without the bytes coming back here in
/// between.
pub(crate) fn tag_with_backend(
    backend: Backend,
    key: &[u8; KEY_SIZE],
    said: &[u8],
    out: &mut [u8; TAG_SIZE],
) {
    let mut poly = Poly1305::new(key);

    #[cfg(test)]
    poly.set_backend(backend);

    finalize(backend, &mut poly.acc, &poly.r, &poly.s, said, out);
}

/// The tag of one message, for a caller that has all of it.
pub fn tag(key: &[u8; KEY_SIZE], said: &[u8], out: &mut [u8; TAG_SIZE]) {
    tag_with_backend(Backend::default(), key, said, out);
}
