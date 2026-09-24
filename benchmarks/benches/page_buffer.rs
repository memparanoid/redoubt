// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! PageBuffer benchmarks: open_mut + fill_bytes_with_pattern
//!
//! `PageBuffer` is `mmap`, `mlock` and `mprotect`, so it exists on unix and
//! nowhere else. What is measured here has no counterpart elsewhere, and the
//! `main` below is what keeps the bench from failing to link on a platform it
//! was never about.

#[cfg(not(unix))]
fn main() {}

#[cfg(unix)]
use criterion::{Criterion, black_box, criterion_group, criterion_main};

#[cfg(unix)]
use redoubt_buffer::{Buffer, PageBuffer};
#[cfg(unix)]
use redoubt_util::fill_bytes_with_pattern;

#[cfg(unix)]
fn bench_open_mut_fill_32(c: &mut Criterion) {
    let mut group = c.benchmark_group("protected_buffer/32B");

    group.bench_function("open_mut_fill/protected", |b| {
        let mut buffer = PageBuffer::new(32).expect("failed to create protected buffer");
        b.iter(|| {
            buffer
                .open_mut(&mut |bytes| {
                    fill_bytes_with_pattern(bytes, black_box(0xAB));
                    Ok(())
                })
                .expect("failed to open_mut protected buffer");
        });
    });

    group.finish();
}

#[cfg(unix)]
fn bench_open_mut_fill_4096(c: &mut Criterion) {
    let mut group = c.benchmark_group("protected_buffer_READ_ONLY/32B");

    group.bench_function("open/protected", |b| {
        let mut buffer = PageBuffer::new(32).expect("failed to create protected buffer");

        b.iter(|| {
            buffer
                .open(&mut |bytes| {
                    black_box(bytes);
                    Ok(())
                })
                .expect("failed to open protected buffer")
        });
    });

    group.finish();
}

#[cfg(unix)]
criterion_group!(benches, bench_open_mut_fill_32, bench_open_mut_fill_4096);
#[cfg(unix)]
criterion_main!(benches);
