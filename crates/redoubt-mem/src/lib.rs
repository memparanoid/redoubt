// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Moving a secret from one place to another without leaving it in a register.
//!
//! # What is wrong with the obvious way
//!
//! ```text
//! core::ptr::copy_nonoverlapping(src, dst, n)     // n known only at run time
//! ```
//!
//! A length the compiler cannot see cannot be unrolled, so this becomes a jump
//! into the C library's `memcpy`. What that does with the bytes is the C
//! library's business, and glibc's business — on a machine with AVX-512 — is
//! to move them through `zmm16` and `zmm17`.
//!
//! Those two are the problem. `zmm16-31` are outside every form of `vzeroall`,
//! and compiled Rust never writes to them, so nothing in the rest of the
//! program will ever overwrite what was left there. It is not a race that is
//! usually won. It is a resting place, and the secret stays in it until the
//! process dies.
//!
//! Registers are not out of reach of memory either. A signal writes the whole
//! register file into the signal frame, **on the process's own stack**; a core
//! dump writes it to disk; a context switch writes it into the kernel. A dirty
//! `zmm16` is one signal away from being bytes somebody can read.
//!
//! # What is here instead
//!
//! [`copy_nonoverlapping`] takes the same arguments in the same order, and
//! calls an assembly routine whose temporaries are known and are erased before
//! it returns. It is a call across an ABI boundary, which is also what stops
//! the optimiser from replacing the body with a copy of its own.
//!
//! The promise is narrow and worth reading as written: on a normal return,
//! every architectural temporary **that routine** put copied bytes into is
//! zero. Not the source, not the destination, not the registers somebody else
//! dirtied, and nothing at all if a fault stops the epilogue from being
//! reached.
//!
//! It is not a replacement for `memcpy` and it does not change what Rust emits
//! for an ordinary move or assignment. It is a thing a caller reaches for
//! where it wants this property, and nowhere else.
//!
//! # Where there is no assembly
//!
//! Anywhere but Unix on `x86_64` or `aarch64`, this is
//! [`core::ptr::copy_nonoverlapping`] and **there is no erasure**. The call
//! compiles and the guarantee does not travel with it.

#![no_std]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

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
