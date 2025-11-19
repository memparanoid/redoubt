// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::coerce::coerce_mem_code_word_into_usize;
use crate::error::MemDecodeError;
use crate::types::*;

#[inline]
pub(crate) fn mem_decode_slice_validate_invariant<T>(
    src: &[T],
    words: &[MemCodeWord],
) -> Result<(), MemDecodeError> {
    if words.is_empty() {
        return Err(MemDecodeError::PreconditionsViolatedError);
    }

    let header_len = coerce_mem_code_word_into_usize(&words[0]);

    if words.len() == 1 && header_len != 0 {
        return Err(MemDecodeError::PreconditionsViolatedError);
    }

    if words.len() != header_len + 1 {
        return Err(MemDecodeError::LengthMismatch {
            expected: header_len,
            got: words.len() - 1,
        });
    }

    if src.len() != header_len {
        return Err(MemDecodeError::LengthMismatch {
            expected: header_len,
            got: src.len(),
        });
    }

    Ok(())
}
