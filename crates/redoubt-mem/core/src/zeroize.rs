// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Zeros written over bytes, by a write the optimizer cannot remove.

use redoubt_asm::Backend;

use crate::backend;

/// Zeros over `count` elements of `T` at `dst`, by a write no optimizer may
/// remove or shorten, however dead it proves the bytes.
///
/// Takes the arguments of [`core::ptr::write_bytes`] without the value, in its
/// order: the count is in elements, not bytes.
///
/// # Safety
///
/// Every requirement of [`core::ptr::write_bytes`] applies: `dst` writable and
/// aligned for `count` elements, and the zeros a value of `T` wherever they are
/// read as one afterwards.
///
/// # Panics
///
/// If `count * size_of::<T>()` overflows a `usize`, which is a range that could
/// not have been valid to ask for.
///
/// ```
/// # use redoubt_mem_core::zeroize;
/// let mut secret = [0x9E_u8, 0x41, 0x17, 0xC3];
///
/// // SAFETY: the array is writable for its own length, and every byte zero is
/// // a `u8`.
/// unsafe { zeroize(secret.as_mut_ptr(), secret.len()) };
///
/// assert_eq!(secret, [0; 4]);
/// ```
#[inline]
pub unsafe fn zeroize<T>(dst: *mut T, count: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { zeroize_using(Backend::default(), dst, count) };
}

/// [`zeroize`], through the backend named.
///
/// # Safety
///
/// As [`zeroize`].
#[inline]
pub unsafe fn zeroize_using<T>(backend: Backend, dst: *mut T, count: usize) {
    let bytes = count
        .checked_mul(core::mem::size_of::<T>())
        .expect("a zeroize's byte count should fit in a usize, as every valid range does");

    // A zero-length write does nothing, and for a zero-sized `T` the pointer is
    // allowed to be dangling — which the routine would still be handed.
    if bytes != 0 {
        // SAFETY: the caller's, verbatim. The cast is between thin pointers of
        // the same address.
        unsafe { backend::zeroize(backend, dst.cast(), bytes) };
    }
}
