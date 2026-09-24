// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Bytes from one place to another, leaving none of them in a register.

use redoubt_asm::Backend;

use crate::backend;

/// `count` elements of `T` from `src` to `dst`, with nothing left behind in a
/// register.
///
/// Takes the arguments of [`core::ptr::copy_nonoverlapping`], in its order:
/// the count is in elements, not bytes.
///
/// # Safety
///
/// Every requirement of [`core::ptr::copy_nonoverlapping`] applies, alignment
/// and non-overlap included. What is added on top is only a promise about
/// registers, and only on a normal return: see the crate documentation for
/// what that promise does not cover, and for the architectures where it is not
/// made at all.
///
/// # Panics
///
/// If `count * size_of::<T>()` overflows a `usize`, which is a copy that could
/// not have been valid to ask for.
///
/// ```
/// # use redoubt_mem::copy_nonoverlapping;
/// let secret = [0x9E_u8, 0x41, 0x17, 0xC3];
/// let mut into = [0_u8; 4];
///
/// // SAFETY: different allocations, and `into` is as long as `secret`.
/// unsafe { copy_nonoverlapping(secret.as_ptr(), into.as_mut_ptr(), secret.len()) };
///
/// assert_eq!(into, secret);
/// ```
#[inline]
pub unsafe fn copy_nonoverlapping<T>(src: *const T, dst: *mut T, count: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { copy_nonoverlapping_with_backend(Backend::default(), src, dst, count) };
}

/// [`copy_nonoverlapping`], through the backend named.
///
/// # Safety
///
/// As [`copy_nonoverlapping`].
#[inline]
pub(crate) unsafe fn copy_nonoverlapping_with_backend<T>(
    backend: Backend,
    src: *const T,
    dst: *mut T,
    count: usize,
) {
    let bytes = count
        .checked_mul(core::mem::size_of::<T>())
        .expect("a copy of more bytes than there are addresses");

    // A zero-length copy is a call that does nothing, and for a zero-sized `T`
    // the pointers are allowed to be dangling — which the routine would still
    // be handed. Neither is worth a call.
    if bytes != 0 {
        // SAFETY: the caller's, verbatim. The cast is between thin pointers of
        // the same address.
        unsafe { backend::copy_nonoverlapping(backend, src.cast(), dst.cast(), bytes) };
    }
}
