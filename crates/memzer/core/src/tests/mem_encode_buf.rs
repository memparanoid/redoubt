// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memcode_core::MemEncodeBuf as InnerMemEncodeBuf;

use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};

#[test]
fn test_inner() {
    fn with_ref(_buf: &InnerMemEncodeBuf) -> bool {
        true
    }

    let wb = MemEncodeBuf::default();
    assert!(with_ref(wb.as_ref()));
}

#[test]
fn test_inner_mut() {
    fn with_mut_ref(buf: &mut InnerMemEncodeBuf) -> bool {
        buf.reset_with_capacity(1);
        buf.drain_byte(&mut 1).expect("Failed to push to buf");
        buf.len() == 1
    }

    let mut buf = MemEncodeBuf::default();

    assert!(with_mut_ref(buf.as_mut()));
}

#[test]
fn test_memzer_traits() {
    let mut buf = MemEncodeBuf::default();
    buf.as_mut().reset_with_capacity(10);
    buf.as_mut()
        .drain_bytes(&mut [0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        .expect("Failed to drain_bytes(..)");

    // Assert (not) zeroization!
    assert!(!buf.is_zeroized());

    buf.self_zeroize();

    // Assert zeroization!
    assert!(buf.is_zeroized());

    buf.assert_zeroize_on_drop();
}
