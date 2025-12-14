// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Trait definitions for memsecret.

/// Zero-copy move operation that zeroizes the source.
///
/// `MemMove` provides a way to transfer data between two locations
/// without creating unzeroized copies, ensuring the source is properly
/// zeroized after the move.
///
/// # Safety
///
/// This trait is safe to implement but requires careful attention:
/// - The source must be fully zeroized after the operation
/// - The destination must contain a complete copy of the source data
/// - No unzeroized intermediate copies should exist
///
/// # Example
///
/// ```rust
/// use redoubt_secret::MemMove;
///
/// let mut src = [197u8; 32];
/// let mut dst = [0u8; 32];
///
/// <[u8; 32]>::mem_move(&mut src, &mut dst);
///
/// // src is now zeroized
/// assert!(src.iter().all(|&b| b == 0));
///
/// // dst contains the original data
/// assert!(dst.iter().all(|&b| b == 197));
/// ```
pub trait MemMove: Sized {
    /// Moves data from `src` to `dst`, zeroizing `src` in the process.
    ///
    /// After this operation:
    /// - `dst` contains the data that was in `src`
    /// - `src` is fully zeroized (no unzeroized copies remain)
    ///
    /// # Panics
    ///
    /// May panic if `dst` is not properly initialized or if sizes don't match.
    fn mem_move(src: &mut Self, dst: &mut Self);
}
