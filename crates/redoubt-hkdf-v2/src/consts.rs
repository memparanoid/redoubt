// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The widths everything here works in.
//!
//! In one place because the compression function, the authenticator and the
//! derivation all quote the same two numbers, and three copies of a width is
//! three places a change has to land.

/// The bytes SHA-256 compresses at a time, and the width HMAC pads its key to.
pub const BLOCK_SIZE: usize = 64;

/// The bytes a digest is, which is also one block of derived output.
pub const HASH_SIZE: usize = 32;

/// The most output a derivation can be asked for.
///
/// RFC 5869 §2.3 counts the blocks with one byte that starts at one, so there
/// are two hundred and fifty-five of them and no more. A caller asking past it
/// is refused rather than served a counter that wrapped.
pub const MAX_OUTPUT_SIZE: usize = 255 * HASH_SIZE;
