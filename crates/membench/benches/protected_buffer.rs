// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ProtectedBuffer benchmarks: open_mut + fill_bytes_with_pattern

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use membuffer::{Buffer, ProtectedBuffer, ProtectionStrategy};
use memutil::fill_bytes_with_pattern;

fn bench_open_mut_fill_32(c: &mut Criterion) {
    let mut group = c.benchmark_group("protected_buffer/32B");

    group.bench_function("open_mut_fill/protected", |b| {
        let mut buffer =
            ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 32).unwrap();
        b.iter(|| {
            buffer
                .open_mut(|bytes| {
                    fill_bytes_with_pattern(bytes, black_box(0xAB));
                    Ok(())
                })
                .unwrap();
        });
    });

    group.bench_function("open_mut_fill/non_protected", |b| {
        let mut buffer =
            ProtectedBuffer::try_create(ProtectionStrategy::MemNonProtected, 32).unwrap();
        b.iter(|| {
            buffer
                .open_mut(|bytes| {
                    fill_bytes_with_pattern(bytes, black_box(0xAB));
                    Ok(())
                })
                .unwrap();
        });
    });

    group.finish();
}

fn bench_open_mut_fill_4096(c: &mut Criterion) {
    let mut group = c.benchmark_group("protected_buffer/4KB");

    group.bench_function("open_mut_fill/protected", |b| {
        let mut buffer =
            ProtectedBuffer::try_create(ProtectionStrategy::MemProtected, 4096).unwrap();
        b.iter(|| {
            buffer
                .open_mut(|bytes| {
                    fill_bytes_with_pattern(bytes, black_box(0xAB));
                    Ok(())
                })
                .unwrap();
        });
    });

    group.bench_function("open_mut_fill/non_protected", |b| {
        let mut buffer =
            ProtectedBuffer::try_create(ProtectionStrategy::MemNonProtected, 4096).unwrap();
        b.iter(|| {
            buffer
                .open_mut(|bytes| {
                    fill_bytes_with_pattern(bytes, black_box(0xAB));
                    Ok(())
                })
                .unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, bench_open_mut_fill_32, bench_open_mut_fill_4096);
criterion_main!(benches);
