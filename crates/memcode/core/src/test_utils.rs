// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use super::types::*;
use super::word_buf::WordBuf;

pub fn tamper_word_buf_for_decode(wb: &mut WordBuf) {
    // Will fail because of coertion error
    wb.as_mut_slice().fill(MemCodeWord::MAX);
}

pub fn tamper_word_buf_for_encode(wb: &mut WordBuf) {
    // Will fail to encode due to impossibility to push elements to wordbuf
    wb.reset_with_capacity(0);
}

pub fn tamper_word_buf_bytes(bytes: &mut Vec<u8>) {
    // Will make bytes.len() % 4 != 0
    bytes.push(0);
}
