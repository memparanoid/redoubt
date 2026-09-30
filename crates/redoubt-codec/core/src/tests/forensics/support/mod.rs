// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use redoubt_forensics::AnyError;
use redoubt_zero::FastZeroizable;

use crate::codec_buffer::RedoubtCodecBuffer;

use needles::{SECRET, TEXT};

/// Writes the secret over and over into `into`, through the copy that erases
/// what it used: a compiler move would leave residue the test caused itself.
pub(crate) fn giving(into: &mut [u8]) {
    for one in into.chunks_mut(SECRET.len()) {
        // SAFETY: `one` is at most as long as the secret, and a constant and a
        // local are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), one.as_mut_ptr(), one.len()) };
    }
}

/// `of` bytes of the secret, over and over.
pub(crate) fn secret_bytes(of: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; of];

    giving(&mut bytes);

    bytes
}

/// `of` bytes of the text secret in a `String`, written the clean way.
pub(crate) fn text(of: usize) -> String {
    let mut text = String::with_capacity(of);

    // SAFETY: every byte written below is ASCII, so what is left spells UTF-8.
    let bytes = unsafe { text.as_mut_vec() };

    bytes.resize(of, 0);

    for one in bytes.chunks_mut(TEXT.len()) {
        // SAFETY: `one` is at most as long as the text, and a constant and a
        // heap block are different allocations.
        unsafe { redoubt_mem::copy_nonoverlapping(TEXT.as_ptr(), one.as_mut_ptr(), one.len()) };
    }

    text
}

/// A buffer holding thirty-two bytes of the secret.
pub(crate) fn a_buffer_holding() -> Result<RedoubtCodecBuffer, AnyError> {
    let mut source = secret_bytes(32);
    let mut buffer = RedoubtCodecBuffer::with_capacity(32);

    buffer.write_slice(&mut source)?;

    source.fast_zeroize();

    Ok(buffer)
}

/// Sixteen bytes of the secret in a `u128`, the widest primitive.
pub(crate) fn a_u128() -> Box<u128> {
    let mut value = Box::new(0_u128);

    giving(bytes_of(&mut *value));

    value
}

/// Thirty-two bytes of the secret in two `u128`s, the whole needle.
pub(crate) fn two_u128() -> Box<[u128; 2]> {
    let mut values = Box::new([0_u128; 2]);

    giving(bytes_of(&mut *values));

    values
}

fn bytes_of<T: Copy>(value: &mut T) -> &mut [u8] {
    // SAFETY: only called with `u128` and arrays of it, which have no padding
    // and a value for every bit pattern, and the borrow is exclusive.
    unsafe {
        core::slice::from_raw_parts_mut(value as *mut T as *mut u8, core::mem::size_of::<T>())
    }
}

/// Takes the value by move and drops it. Not inlined, so the move is not
/// folded away.
#[inline(never)]
pub(crate) fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the value by move and never drops it. Not inlined, so the move is not
/// folded away.
#[inline(never)]
pub(crate) fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}
