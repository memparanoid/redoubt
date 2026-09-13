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

// Payload lives in `rax`, `rcx` and the low 128 bits of `xmm0-3` on x86_64, in
// `v0-v3` and `x3-x4` on aarch64, and every exit erases them. A leaf: nothing
// on the stack, no calls, no callee-saved register touched.
//
// Legacy SSE and Advanced SIMD on purpose, as in `copy.rs`: a write to `xmm0`
// leaves the upper lanes of `zmm0` alone, so a routine that never writes past
// 128 bits has no upper lanes to erase.
#[cfg(all(
    target_family = "unix",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
unsafe extern "C" {
    /// The routine itself, in whichever `asm/swap_*.S` was assembled.
    ///
    /// # Safety
    ///
    /// `a` and `b` readable and writable for `bytes`, and the two ranges must
    /// not overlap.
    fn redoubt_mem_swap(a: *mut u8, b: *mut u8, bytes: usize);
}

/// Exchanges two values, with neither left behind in a register.
///
/// The same shape as [`core::mem::swap`], and the same meaning: what each
/// reference points at afterwards is what the other pointed at before,
/// including a value that owns a heap allocation. Nothing is dropped and
/// nothing is moved through Rust, so no temporary of `T` is ever materialised
/// where the compiler could leave a copy of it.
///
/// # Example
///
/// ```rust
/// let mut secret = [0xAB_u8; 32];
/// let mut empty = [0_u8; 32];
///
/// redoubt_mem::swap(&mut secret, &mut empty);
///
/// assert_eq!(empty, [0xAB_u8; 32]);
/// assert_eq!(secret, [0_u8; 32]);
/// ```
#[inline]
pub fn swap<T>(a: &mut T, b: &mut T) {
    // SAFETY: exclusive references are aligned, valid for reads and writes of
    // one `T`, and cannot overlap.
    unsafe { swap_nonoverlapping(a, b, 1) };
}

/// `count` elements of `T` exchanged between two disjoint ranges.
///
/// The same arguments, in the same order, as
/// [`core::ptr::swap_nonoverlapping`] — count in elements, not bytes. Nothing
/// is allocated and nothing is dropped, and the initialisation state of both
/// ranges is preserved down to the padding.
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
    #[cfg(all(
        target_family = "unix",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let bytes = count
            .checked_mul(core::mem::size_of::<T>())
            .expect("a swap of more bytes than there are addresses");

        // A zero-length swap is a call that does nothing, and for a zero-sized
        // `T` the pointers are allowed to be dangling — which the routine
        // would still be handed. Neither is worth a call.
        if bytes != 0 {
            // SAFETY: the caller's, verbatim. The cast is between thin
            // pointers of the same address.
            unsafe { redoubt_mem_swap(a.cast(), b.cast(), bytes) };
        }
    }

    #[cfg(not(all(
        target_family = "unix",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    // SAFETY: the caller's, verbatim. No erasure is promised here, and the
    // crate documentation says so.
    unsafe {
        core::ptr::swap_nonoverlapping(a, b, count);
    }
}
