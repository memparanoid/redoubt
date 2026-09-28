// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Bytes to hex digits.

use redoubt_asm::Backend;

use crate::backend;
use crate::error::HexError;

/// `src` as lowercase hex digits in `dst`, two per byte; where there is
/// assembly for the target, in a time that says nothing about the bytes and
/// with none of them left in a register.
///
/// ```
/// let mut digits = [0_u8; 4];
///
/// redoubt_hex::bytes_to_hex(&[0x9E, 0x41], &mut digits)?;
///
/// assert_eq!(&digits, b"9e41");
/// # Ok::<(), redoubt_hex::HexError>(())
/// ```
///
/// # Errors
///
/// [`HexError::WrongDestination`] when `dst` is not twice as long as `src`.
pub fn bytes_to_hex(src: &[u8], dst: &mut [u8]) -> Result<(), HexError> {
    bytes_to_hex_with_backend(Backend::default(), src, dst)
}

/// [`bytes_to_hex`], through the backend named.
pub(crate) fn bytes_to_hex_with_backend(
    backend: Backend,
    src: &[u8],
    dst: &mut [u8],
) -> Result<(), HexError> {
    if dst.len() != 2 * src.len() {
        return Err(HexError::WrongDestination);
    }

    // SAFETY: `dst` was just found twice as long as `src`.
    unsafe { backend::bytes_to_hex(backend, src, dst) };

    Ok(())
}
