// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::traits::*;
use crate::types::*;
use crate::word_buf::WordBuf;

#[test]
fn test_vec_drain_into_ok() {
    let mut src = [MemCodeUnit::MAX; 64].to_vec();

    let required_capacity = src.mem_encode_required_capacity();
    assert_eq!(required_capacity, 65);

    let mut wb = WordBuf::new(required_capacity);
    let result = src.drain_into(&mut wb);
    assert!(result.is_ok());

    let expected = {
        let mut expected = [MemCodeUnit::MAX as MemCodeWord; 65];
        expected[0] = 64;
        expected
    };
    assert_eq!(wb.as_slice(), &expected);

    // Assert zeroization!
    assert!(src.iter().all(|&b| b == 0));
}
