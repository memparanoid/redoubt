// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::traits::{MemDrainDecode, MemDrainEncode};
use crate::word_buf::WordBuf;

use super::perm_struct::PermStruct;

#[test]
fn test_perm_struct_zeroize() {
    let mut ps = PermStruct::new();
    assert!(ps.is_zeroized());
    assert!(!ps.is_filled());

    ps.fill();

    assert!(ps.is_filled());
    assert!(!ps.is_zeroized());

    ps.zeroize();

    assert!(ps.is_zeroized());
    assert!(!ps.is_filled());
}

#[test]
fn test_perm_struct_is_zeroized_after_drain_into() {
    let mut ps = PermStruct::new();

    ps.fill();
    assert!(!ps.is_zeroized());

    let mut wb = WordBuf::new(ps.mem_encode_required_capacity());
    let result = ps.drain_into(&mut wb);

    assert!(result.is_ok());

    // Assert zeroization
    assert!(ps.is_zeroized());
}

#[test]
fn fuzzy_testing() {
    let mut ps = PermStruct::new();

    ps.permute(25_000, |words| {
        let mut permuted_ps = PermStruct::new();
        permuted_ps.zeroize();

        let result = permuted_ps.drain_from(words);

        assert!(result.is_ok());
        assert!(permuted_ps.is_filled());

        // Assert zeroization!
        assert!(words.iter().all(|&b| b == 0));
    });
}
