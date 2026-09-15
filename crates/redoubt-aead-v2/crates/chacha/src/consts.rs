// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! How the state is laid out, and what sits at the top of it.

/// Words the state is held in.
pub(crate) const WORDS: usize = 16;

/// Double rounds, which is half of the twenty the name counts.
pub(crate) const DOUBLE_ROUNDS: usize = 10;

/// "expand 32-byte k", which is what the first four words spell.
///
/// The words and not the string: they are read little-endian, and writing them
/// out is one fewer conversion to get wrong than writing the bytes.
pub(crate) const PREAMBLE: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Where the key words start in the state.
pub(crate) const KEY_AT: usize = 4;

/// Where the counter starts in the state, and where the nonce follows it.
pub(crate) const COUNTER_AT: usize = 12;
