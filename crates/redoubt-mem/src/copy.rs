// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Bytes from one place to another, leaving none of them in a register.

// Three paths inside, chosen by length alone: general registers up to 32
// bytes, SSE or NEON in the middle, and a string move or a wide loop past
// that. The erasure is a handful of instructions at the end, so it is most of
// the cost of a short copy and nothing at all in a long one — which is the
// argument for reaching for this at an API boundary rather than around every
// copy inside one.
#[cfg(all(
    target_family = "unix",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
unsafe extern "C" {
    /// The routine itself, in whichever `asm/copy_*.S` was assembled.
    ///
    /// # Safety
    ///
    /// `src` readable and `dst` writable for `bytes`, and the two ranges must
    /// not overlap.
    fn redoubt_copy_bytes(src: *const u8, dst: *mut u8, bytes: usize);
}

/// `count` elements of `T` from `src` to `dst`, with nothing left behind in a
/// register.
///
/// The same arguments, in the same order, as
/// [`core::ptr::copy_nonoverlapping`] — count in elements, not bytes.
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
    #[cfg(all(
        target_family = "unix",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let bytes = count
            .checked_mul(core::mem::size_of::<T>())
            .expect("a copy of more bytes than there are addresses");

        // A zero-length copy is a call that does nothing, and for a
        // zero-sized `T` the pointers are allowed to be dangling — which the
        // routine would still be handed. Neither is worth a call.
        if bytes != 0 {
            // SAFETY: the caller's, verbatim. The cast is between thin
            // pointers of the same address.
            unsafe { redoubt_copy_bytes(src.cast(), dst.cast(), bytes) };
        }
    }

    #[cfg(not(all(
        target_family = "unix",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    // SAFETY: the caller's, verbatim. No erasure is promised here, and the
    // crate documentation says so.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, count);
    }
}
