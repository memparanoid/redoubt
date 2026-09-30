// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use redoubt_forensics::{AnyError, Watching};

use needles::{SECRET, backwards, next_box_key_backwards};

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
