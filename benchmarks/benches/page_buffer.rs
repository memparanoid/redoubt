// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! PageBuffer benchmarks: open_mut + fill_bytes_with_pattern

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use membuffer::{Buffer, PageBuffer, ProtectionStrategy};
use redoubt_util::fill_bytes_with_pattern;

fn bench_open_mut_fill_32(c: &mut Criterion) {
    let mut group = c.benchmark_group("protected_buffer/32B");

    group.bench_function("open_mut_fill/protected", |b| {
        let mut buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 32)
            .expect("failed to create protected buffer");
        b.iter(|| {
            buffer
                .open_mut(&mut |bytes| {
                    fill_bytes_with_pattern(bytes, black_box(0xAB));
                    Ok(())
                })
                .expect("failed to open_mut protected buffer");
        });
    });

    group.bench_function("open_mut_fill/non_protected", |b| {
        let mut buffer = PageBuffer::new(ProtectionStrategy::MemNonProtected, 32)
            .expect("failed to create non-protected buffer");
        b.iter(|| {
            buffer
                .open_mut(&mut |bytes| {
                    fill_bytes_with_pattern(bytes, black_box(0xAB));
                    Ok(())
                })
                .expect("failed to open_mut non-protected buffer");
        });
    });

    group.finish();
}

fn bench_open_mut_fill_4096(c: &mut Criterion) {
    let mut group = c.benchmark_group("protected_buffer_READ_ONLY/32B");

    group.bench_function("open/protected", |b| {
        let mut buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 32)
            .expect("failed to create protected buffer");

        b.iter(|| {
            buffer
                .open(&mut |bytes| {
                    black_box(bytes);
                    Ok(())
                })
                .expect("failed to open protected buffer")
        });
    });

    group.bench_function("open/non_protected", |b| {
        let mut buffer = PageBuffer::new(ProtectionStrategy::MemNonProtected, 32)
            .expect("failed to create non-protected buffer");

        b.iter(|| {
            buffer
                .open(&mut |bytes| {
                    black_box(bytes);
                    Ok(())
                })
                .expect("failed to open non-protected buffer");
        });
    });

    group.finish();
}

criterion_group!(benches, bench_open_mut_fill_32, bench_open_mut_fill_4096);
criterion_main!(benches);
