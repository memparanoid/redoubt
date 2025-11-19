// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{MemBytesRequired, MemDecode, MemEncode};

#[test]
fn test_nested_collections_depth_1() {
    let mut original = (1u8..=255).collect::<Vec<u8>>();
    let mut buf = MemEncodeBuf::new(
        original
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    // Assert (not) zeroization!
    assert!(original.iter().any(|b| *b != 0));

    original
        .drain_into(&mut buf)
        .expect("Failed to drain_into(..)");

    let mut recovered: Vec<u8> = Vec::new();
    let consumed = recovered
        .drain_from(buf.as_mut_slice())
        .expect("Failed to drain_from(..)");

    // Assert zeroization!
    assert!(original.iter().all(|b| *b == 0));
    assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
}

#[test]
fn test_nested_collections_depth_2() {
    let mut original = vec![(1u8..=255).collect::<Vec<u8>>()];
    let mut buf = MemEncodeBuf::new(
        original
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    // Assert (not) zeroization!
    assert!(original.iter().any(|v| v.iter().any(|b| *b != 0)));

    original
        .drain_into(&mut buf)
        .expect("Failed to drain_into(..)");

    let mut recovered: Vec<Vec<u8>> = Vec::new();
    let consumed = recovered
        .drain_from(buf.as_mut_slice())
        .expect("Failed to drain_from(..)");

    // Assert zeroization!
    assert!(original.iter().all(|v| v.iter().all(|b| *b == 0)));
    assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
}

#[test]
fn test_nested_collections_depth_3() {
    let mut original = vec![vec![(1u8..=255).collect::<Vec<u8>>()]];
    let mut buf = MemEncodeBuf::new(
        original
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    // Assert (not) zeroization!
    assert!(
        original
            .iter()
            .any(|v1| v1.iter().any(|v2| v2.iter().any(|b| *b != 0)))
    );

    original
        .drain_into(&mut buf)
        .expect("Failed to drain_into(..)");

    let mut recovered: Vec<Vec<Vec<u8>>> = Vec::new();
    let consumed = recovered
        .drain_from(buf.as_mut_slice())
        .expect("Failed to drain_from(..)");

    // Assert zeroization!
    assert!(
        original
            .iter()
            .all(|v1| v1.iter().all(|v2| v2.iter().all(|b| *b == 0)))
    );
    assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
}

#[test]
fn test_nested_collections_depth_4() {
    let mut original = vec![vec![vec![(1u8..=255).collect::<Vec<u8>>()]]];
    let mut buf = MemEncodeBuf::new(
        original
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    // Assert (not) zeroization!
    assert!(original.iter().any(|v1| {
        v1.iter()
            .any(|v2| v2.iter().any(|v3| v3.iter().any(|b| *b != 0)))
    }));

    original
        .drain_into(&mut buf)
        .expect("Failed to drain_into(..)");

    let mut recovered: Vec<Vec<Vec<Vec<u8>>>> = Vec::new();
    let consumed = recovered
        .drain_from(buf.as_mut_slice())
        .expect("Failed to drain_from(..)");

    // Assert zeroization!
    assert!(original.iter().all(|v1| {
        v1.iter()
            .all(|v2| v2.iter().all(|v3| v3.iter().all(|b| *b == 0)))
    }));
    assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
}

#[test]
fn test_nested_collections_depth_5() {
    let mut original = vec![vec![vec![vec![(1u8..=255).collect::<Vec<u8>>()]]]];
    let mut buf = MemEncodeBuf::new(
        original
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    // Assert (not) zeroization!
    assert!(original.iter().any(|v1| v1.iter().any(|v2| {
        v2.iter()
            .any(|v3| v3.iter().any(|v4| v4.iter().any(|b| *b != 0)))
    })));

    original
        .drain_into(&mut buf)
        .expect("Failed to drain_into(..)");

    let mut recovered: Vec<Vec<Vec<Vec<Vec<u8>>>>> = Vec::new();
    let consumed = recovered
        .drain_from(buf.as_mut_slice())
        .expect("Failed to drain_from(..)");

    // Assert zeroization!
    assert!(original.iter().all(|v1| v1.iter().all(|v2| {
        v2.iter()
            .all(|v3| v3.iter().all(|v4| v4.iter().all(|b| *b == 0)))
    })));
    assert!(buf.as_slice()[..consumed].iter().all(|b| *b == 0));
}
