// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub(crate) mod needles;

use crate::error::BufferError;
use crate::traits::Buffer;

use needles::SECRET;

/// The callback an `open_mut` is handed to write the secret, through the copy
/// that erases what it used: a plain assignment is whatever move the compiler
/// emits, and the test does not get to cause the thing it is measuring.
pub(crate) fn writing_the_secret(slice: &mut [u8]) -> Result<(), BufferError> {
    // SAFETY: the buffer is the secret's length, and a constant and a buffer
    // are different allocations.
    unsafe { redoubt_mem::copy_nonoverlapping(SECRET.as_ptr(), slice.as_mut_ptr(), SECRET.len()) };

    Ok(())
}

/// A buffer filled with the secret, for a section that measures something
/// else. Never inside a capture: there the operation is called directly.
pub(crate) fn fill(buffer: &mut dyn Buffer) -> Result<(), BufferError> {
    buffer.open_mut(&mut writing_the_secret)
}

/// A reader that takes the slice and does nothing a compiler may remove.
pub(crate) fn used(slice: &[u8]) -> Result<(), BufferError> {
    core::hint::black_box(slice);

    Ok(())
}

/// Takes the buffer by move and drops it. Not inlined, so the move is not
/// folded away.
#[inline(never)]
pub(crate) fn let_go<T>(value: T) {
    core::hint::black_box(&value);
}

/// Takes the buffer by move and never drops it. Not inlined, so the move is
/// not folded away.
#[inline(never)]
pub(crate) fn hold_on<T>(value: T) {
    core::mem::forget(core::hint::black_box(value));
}
