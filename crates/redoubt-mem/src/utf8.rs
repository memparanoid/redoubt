// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether bytes spell UTF-8, leaving none of them in a register.

#[cfg(all(
    target_family = "unix",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
unsafe extern "C" {
    /// The routine itself, in whichever `asm/utf8_*.S` was assembled.
    ///
    /// # Safety
    ///
    /// `bytes` readable for `len`, and `answer` writable for one byte.
    fn redoubt_mem_utf8_valid(bytes: *const u8, len: usize, answer: *mut u8);
}

/// Whether `bytes` are UTF-8, as [`core::str::from_utf8`] would answer, with
/// none of them left behind in a register.
///
/// Not constant time: how long it takes says where the multibyte sequences are
/// and where the first byte that is not UTF-8 is. Where there is no assembly
/// this is [`core::str::from_utf8`] and there is no erasure.
///
/// ```
/// assert!(redoubt_mem::is_utf8("añejo".as_bytes()));
/// assert!(!redoubt_mem::is_utf8(&[0xC0, 0x80]));
/// ```
#[inline]
pub fn is_utf8(bytes: &[u8]) -> bool {
    #[cfg(all(
        target_family = "unix",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let mut answer = 0_u8;

        // SAFETY: the slice is readable for its own length, which the routine
        // does not read past, and `answer` is one byte this frame owns.
        unsafe { redoubt_mem_utf8_valid(bytes.as_ptr(), bytes.len(), &mut answer) };

        answer == 1
    }

    #[cfg(not(all(
        target_family = "unix",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        core::str::from_utf8(bytes).is_ok()
    }
}
