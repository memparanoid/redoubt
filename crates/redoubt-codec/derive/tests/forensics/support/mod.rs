// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use needles::NEEDLE;

/// Writes the needle over and over into `into`, through the copy that erases
/// what it used: a compiler move would leave residue the test caused itself.
pub(crate) fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(NEEDLE.len()) {
        // SAFETY: `one` is at most as long as the needle, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(NEEDLE.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// `of` bytes of the needle, over and over.
pub(crate) fn bytes(of: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; of];

    giving(&mut bytes);

    bytes
}

/// `of` bytes of the needle in a `String`, written the same way.
pub(crate) fn text(of: usize) -> String {
    let mut text = String::with_capacity(of);

    // SAFETY: every byte written below is ASCII, so what is left spells UTF-8.
    let bytes = unsafe { text.as_mut_vec() };

    bytes.resize(of, 0);

    giving(bytes);

    text
}

/// The needle in a `u128`, boxed so no stack slot is left holding it.
pub(crate) fn a_u128() -> Box<u128> {
    let mut value = Box::new(0_u128);

    // SAFETY: a `u128` has no padding and a value for every bit pattern, and
    // the borrow is exclusive.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut *value as *mut u128).cast::<u8>(),
            core::mem::size_of::<u128>(),
        )
    };

    giving(bytes);

    value
}
