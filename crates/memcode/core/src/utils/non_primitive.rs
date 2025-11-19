// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::coerce::coerce_mem_code_word_into_usize;
use crate::error::{MemDecodeError, MemEncodeError};
use crate::take::try_take_into;
use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

// MemDrainEncode utils
pub fn mem_encode_required_capacity(fields: &[&dyn MemDrainEncode]) -> usize {
    let fields_capacity = fields
        .iter()
        .map(|f| f.mem_encode_required_capacity())
        .sum::<usize>();
    fields_capacity + 1
}

fn try_drain_into(
    fields: &mut [&mut dyn ZeroizableMemDrainEncode],
    buf: &mut WordBuf,
) -> Result<(), MemEncodeError> {
    let mut required_capacity = {
        let fields_required_capacity: usize = fields
            .iter()
            .map(|f| f.mem_encode_required_capacity())
            .sum();
        fields_required_capacity
    };

    let coered_required_capacity = try_take_into::<usize, MemCodeWord>(&mut required_capacity)?;

    buf.push(coered_required_capacity)?;

    for field in fields {
        (*field).drain_into(buf)?;
    }

    Ok(())
}

fn try_drain_into_with_zeroization(
    fields: &mut [&mut dyn ZeroizableMemDrainEncode],
    buf: &mut WordBuf,
) -> Result<(), MemEncodeError> {
    let result = try_drain_into(fields, buf);

    if result.is_err() {
        buf.zeroize();

        for field in fields {
            field.zeroize();
        }
    }

    result
}

pub fn drain_into(
    fields: &mut [&mut dyn ZeroizableMemDrainEncode],
    buf: &mut WordBuf,
) -> Result<(), MemEncodeError> {
    try_drain_into_with_zeroization(fields, buf)
}

// MemDrainDecode utils
pub fn mem_decode_validate_invariant(
    words: &[MemCodeWord],
    fields_len: usize,
) -> Result<(), MemDecodeError> {
    if words.is_empty() {
        return Err(MemDecodeError::PreconditionsViolatedError);
    }

    let header_len = coerce_mem_code_word_into_usize(&words[0]);

    if words.len() != header_len + 1 {
        return Err(MemDecodeError::LengthMismatch {
            expected: header_len,
            got: words.len() - 1,
        });
    }

    let mut current_header = 1;

    for _ in 0..fields_len {
        if current_header >= words.len() {
            return Err(MemDecodeError::PreconditionsViolatedError);
        }

        current_header += coerce_mem_code_word_into_usize(&words[current_header]) + 1;
    }

    Ok(())
}

fn try_drain_from(
    fields: &mut [&mut dyn ZeroizableMemDrainDecode],
    words: &mut [MemCodeWord],
) -> Result<(), MemDecodeError> {
    mem_decode_validate_invariant(words, fields.len())?;

    let mut cursor = 1;

    for field in fields {
        let start = cursor;
        let field_header_len = coerce_mem_code_word_into_usize(&words[start]);
        let end = start + field_header_len + 1;

        let field_words = &mut words[start..end];
        field.drain_from(field_words)?;

        cursor = end;
    }

    Ok(())
}

fn try_drain_from_with_zeroization(
    fields: &mut [&mut dyn ZeroizableMemDrainDecode],
    words: &mut [MemCodeWord],
) -> Result<(), MemDecodeError> {
    let result = try_drain_from(fields, words);

    words.zeroize();

    if result.is_err() {
        for field in fields {
            field.zeroize();
        }
    }

    result
}

pub fn drain_from(
    fields: &mut [&mut dyn ZeroizableMemDrainDecode],
    words: &mut [MemCodeWord],
) -> Result<(), MemDecodeError> {
    try_drain_from_with_zeroization(fields, words)
}
