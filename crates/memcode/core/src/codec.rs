// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::traits::DefaultValue;
use crate::types::*;

use super::error::CodecError;

pub fn calculate_len_for_bytes(current_size: usize) -> usize {
    current_size * 4
}

fn try_take_words_from_bytes(bytes: &mut [u8]) -> Result<Vec<MemCodeWord>, CodecError> {
    if bytes.len() % 4 != 0 {
        return Err(CodecError::InvalidWordStreamLenError { got: bytes.len() });
    }

    let mut fv = Vec::with_capacity(bytes.len() / 4);
    fv.resize_with(bytes.len() / 4, MemCodeWord::default_zero_value);

    for (idx, chunk) in bytes.chunks_exact_mut(4).enumerate() {
        let mut chunk_u8_4: [u8; 4] =
            <[u8; 4]>::try_from(&*chunk).expect("Infallible: bytes.len() is multiple of 4");

        // wipe asap
        chunk.zeroize();

        let word: MemCodeWord = MemCodeWord::from_le_bytes(chunk_u8_4);

        // wipe asap
        chunk_u8_4.zeroize();

        fv[idx] = word;
    }

    Ok(fv)
}

pub fn try_take_words_from_bytes_and_zeroize(
    bytes: &mut [u8],
) -> Result<Vec<MemCodeWord>, CodecError> {
    let result = try_take_words_from_bytes(bytes);
    bytes.zeroize();
    result
}
