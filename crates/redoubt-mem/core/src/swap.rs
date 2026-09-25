// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Two values exchanged in place, leaving neither of them in a register.
//!
//! # Why a swap and not two copies
//!
//! A swap through [`crate::copy_nonoverlapping`] would need somewhere to put
//! the first value while the second is written over it, and that somewhere is
//! a buffer as wide as `T`. This does it a chunk at a time out of registers it
//! then erases, so nothing of either value is ever anywhere but the two places
//! that already held them.
//!
//! It is also the only shape that works for a `T` that owns something. Moving
//! the bytes of a `Vec` copies its pointer, and then two owners hold the same
//! allocation; a swap leaves exactly one owner at each address, which is what
//! `mem::swap` means.

use redoubt_asm::Backend;

use crate::backend;

/// Exchanges two values, with neither left behind in a register.
///
/// The shape of [`core::mem::swap`], and its meaning: what each reference
/// points at afterwards is what the other pointed at before, including a value
/// that owns a heap allocation. Nothing is dropped and nothing is moved through
/// Rust, so no temporary of `T` is ever materialised where the compiler could
/// leave a copy of it.
///
/// # Example
///
/// ```rust
/// let mut secret = [0xAB_u8; 32];
/// let mut empty = [0_u8; 32];
///
/// redoubt_mem_core::swap(&mut secret, &mut empty);
///
/// assert_eq!(empty, [0xAB_u8; 32]);
/// assert_eq!(secret, [0_u8; 32]);
/// ```
#[inline]
pub fn swap<T>(a: &mut T, b: &mut T) {
    swap_with_backend(Backend::default(), a, b);
}

/// [`swap`], through the backend named.
#[inline]
pub fn swap_with_backend<T>(backend: Backend, a: &mut T, b: &mut T) {
    // SAFETY: exclusive references are aligned, valid for reads and writes of
    // one `T`, and cannot overlap.
    unsafe { swap_nonoverlapping_with_backend(backend, a, b, 1) };
}

/// `count` elements of `T` exchanged between two disjoint ranges.
///
/// Takes the arguments of [`core::ptr::swap_nonoverlapping`], in its order:
/// the count is in elements, not bytes. Nothing is allocated and nothing is
/// dropped, and the initialisation state of both ranges is preserved down to
/// the padding.
///
/// # Safety
///
/// Every requirement of [`core::ptr::swap_nonoverlapping`] applies, alignment
/// and non-overlap included. What is added on top is only a promise about
/// registers, and only on a normal return: see the crate documentation for
/// what that promise does not cover, and for the architectures where it is not
/// made at all.
///
/// # Panics
///
/// If `count * size_of::<T>()` overflows a `usize`, which is a range that
/// cannot exist.
#[inline]
pub unsafe fn swap_nonoverlapping<T>(a: *mut T, b: *mut T, count: usize) {
    // SAFETY: the caller's, verbatim.
    unsafe { swap_nonoverlapping_with_backend(Backend::default(), a, b, count) };
}

/// [`swap_nonoverlapping`], through the backend named.
///
/// # Safety
///
/// As [`swap_nonoverlapping`].
#[inline]
pub unsafe fn swap_nonoverlapping_with_backend<T>(
    backend: Backend,
    a: *mut T,
    b: *mut T,
    count: usize,
) {
    let bytes = count
        .checked_mul(core::mem::size_of::<T>())
        .expect("a swap of more bytes than there are addresses");

    // A zero-length swap is a call that does nothing, and for a zero-sized `T`
    // the pointers are allowed to be dangling — which the routine would still
    // be handed. Neither is worth a call.
    if bytes != 0 {
        // SAFETY: the caller's, verbatim. The cast is between thin pointers of
        // the same address.
        unsafe { backend::swap_nonoverlapping(backend, a.cast(), b.cast(), bytes) };
    }
}
