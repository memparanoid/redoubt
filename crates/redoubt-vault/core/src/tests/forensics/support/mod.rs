// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use redoubt_alloc::RedoubtVec;
use redoubt_buffer::BufferError;
use redoubt_forensics::{AnyError, Watching};

use crate::master_key::derive_next_cipherbox_key;

use needles::{SECRET, backwards, box_key_width, next_box_key_backwards};

/// The secret and the key the next box works with, in one photograph.
pub(crate) fn watch_the_secret_and_the_key() -> Result<Watching, AnyError> {
    Ok(Watching::start(&[
        ("secret", &backwards()),
        ("key", &next_box_key_backwards()?),
    ])?)
}

/// Writes the secret over and over into `into`, through the copy that erases
/// what it used: a compiler move would leave residue the test caused itself.
pub(crate) fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// A field holding the secret.
pub(crate) fn a_field() -> RedoubtVec<u8> {
    let mut source = vec![0_u8; 32];

    giving(&mut source);

    let mut field = RedoubtVec::default();

    field.replace_from_mut_slice(&mut source);

    field
}

/// A copy of the key a box encrypts with, made by the copy that erases what it
/// used: `to_vec` would be the C library's `memcpy`.
pub(crate) fn a_key() -> Result<Vec<u8>, AnyError> {
    let opened = derive_next_cipherbox_key(box_key_width())?;
    let mut key = vec![0_u8; opened.len()];

    // SAFETY: `key` was made as long as `opened`, and the two are different
    // allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(opened.as_ptr(), key.as_mut_ptr(), key.len()) };

    Ok(key)
}

/// A callback that copies what it is handed into `into`, through the copy that
/// erases what it used.
pub(crate) fn copying_into(into: &mut [u8]) -> impl FnMut(&[u8]) -> Result<(), BufferError> + '_ {
    move |key| {
        let len = into.len().min(key.len());

        // SAFETY: `len` fits both, and the key's page and `into` are different
        // allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(key.as_ptr(), into.as_mut_ptr(), len) };

        Ok(())
    }
}
