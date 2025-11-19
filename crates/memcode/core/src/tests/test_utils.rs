// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::test_utils::{
    tamper_word_buf_bytes, tamper_word_buf_for_decode, tamper_word_buf_for_encode,
};
use crate::traits::*;
use crate::word_buf::WordBuf;

use super::structs::plain::PlainStructure;

#[test]
fn test_tamper_word_buf_for_decode() {
    let mut bytes = {
        let mut ps = PlainStructure::default();

        let mut wb = WordBuf::new(ps.mem_encode_required_capacity());
        ps.drain_into(&mut wb).expect("Failed to drain to WordBuf");

        let bytes = wb.to_bytes();

        // Assert zeroization!
        assert!(ps.is_zeroized());
        assert!(wb.as_slice().iter().all(|b| *b == 0));

        bytes
    };

    let mut recovered_wb = WordBuf::new(0);
    recovered_wb
        .try_from_bytes(bytes.as_mut_slice())
        .expect("Failed to load bytes");

    assert!(bytes.as_slice().iter().all(|b| *b == 0));
    tamper_word_buf_for_decode(&mut recovered_wb);

    let mut recovered_ps = PlainStructure::default();
    let result = recovered_ps.drain_from(recovered_wb.as_mut_slice());

    assert!(result.is_err());

    assert!(recovered_wb.as_slice().iter().all(|b| *b == 0));
    assert!(recovered_ps.is_zeroized());
}

#[test]
fn test_tamper_word_buf_for_encode() {
    let mut ps = PlainStructure::default();

    let mut wb = WordBuf::new(ps.mem_encode_required_capacity());
    tamper_word_buf_for_encode(&mut wb);

    let result = ps.drain_into(&mut wb);

    assert!(result.is_err());

    // Assert zeroization!
    assert!(ps.is_zeroized());
    assert!(wb.as_slice().iter().all(|b| *b == 0));
}

#[test]
fn test_tamper_word_buf_bytes() {
    let mut bytes = {
        let mut ps = PlainStructure::default();

        let mut wb = WordBuf::new(ps.mem_encode_required_capacity());
        ps.drain_into(&mut wb).expect("Failed to drain to WordBuf");

        let bytes = wb.to_bytes();

        // Assert zeroization!
        assert!(ps.is_zeroized());
        assert!(wb.as_slice().iter().all(|b| *b == 0));

        bytes
    };

    tamper_word_buf_bytes(&mut bytes);

    let mut recovered_wb = WordBuf::new(0);
    let result = recovered_wb.try_from_bytes(bytes.as_mut_slice());

    assert!(result.is_err());

    // Assert zeroization!
    assert!(bytes.as_slice().iter().all(|b| *b == 0));
    assert!(recovered_wb.as_slice().iter().all(|b| *b == 0));
}
