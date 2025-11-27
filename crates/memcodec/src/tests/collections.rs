// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use membuffer::Buffer;

use crate::traits::{BytesRequired, Encode};

#[test]
fn test_huge_vec() {
    use std::time::Instant;

    let iterations = 1000 as usize;
    let start = Instant::now();

    for _ in 0..iterations {
        let mut vec = vec![u8::MAX; 1024];
        let bytes_required = vec
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        let mut buf = Buffer::new(bytes_required);

        vec.encode_into(&mut buf).expect("Failed to drain_into(..)");
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);

    println!("Total: {:?}, Per iter: {:?}", elapsed, per_iter);
}

#[test]
fn test_bulk_copy_only() {
    use std::time::Instant;

    let iterations = 100_000 as usize;
    // Pre-allocate buffer once
    let vec = vec![u8::MAX; 1024];
    let buf_size = vec
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    let mut buf = Buffer::new(buf_size);

    let start = Instant::now();

    for _ in 0..iterations {
        let mut vec = vec![u8::MAX; 1024];

        // Direct bulk copy test - skip mem_bytes_required
        vec.encode_into(&mut buf).expect("Failed to drain_into(..)");

        std::hint::black_box(&buf);

        buf.clear();
    }

    let elapsed = start.elapsed();
    let per_iter = elapsed / (iterations as u32);

    println!(
        "Bulk copy only - Total: {:?}, Per iter: {:?}",
        elapsed, per_iter
    );
}
