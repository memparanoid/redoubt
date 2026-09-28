// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Hex digits to bytes.

use redoubt_asm::Backend;

use crate::backend;
use crate::error::HexError;

/// The bytes the hex digits in `src` spell, in `dst`; where there is assembly
/// for the target, in a time that says nothing about the digits and with none
/// of them left in a register.
///
/// Both cases are read. Every character is read whatever the ones before it
/// were, so a refusal says that one was not a digit and not which.
///
/// ```
/// let mut bytes = [0_u8; 2];
///
/// redoubt_hex::hex_to_bytes(b"9E41", &mut bytes)?;
///
/// assert_eq!(bytes, [0x9E, 0x41]);
/// # Ok::<(), redoubt_hex::HexError>(())
/// ```
///
/// # Errors
///
/// [`HexError::OddLength`] when `src` is not an even count,
/// [`HexError::WrongDestination`] when `dst` is not half as long, and
/// [`HexError::NotHex`] when a character is not a hex digit, `dst` then all
/// zeros.
pub fn hex_to_bytes(src: &[u8], dst: &mut [u8]) -> Result<(), HexError> {
    hex_to_bytes_with_backend(Backend::default(), src, dst)
}

/// [`hex_to_bytes`], through the backend named.
pub(crate) fn hex_to_bytes_with_backend(
    backend: Backend,
    src: &[u8],
    dst: &mut [u8],
) -> Result<(), HexError> {
    if !src.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }

    if dst.len() != src.len() / 2 {
        return Err(HexError::WrongDestination);
    }

    // SAFETY: `src` was just found even, and `dst` half as long.
    if unsafe { backend::hex_to_bytes(backend, src, dst) } {
        Ok(())
    } else {
        Err(HexError::NotHex)
    }
}
