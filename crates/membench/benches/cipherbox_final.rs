// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! CipherBox final benchmarks: per-field operations at various data sizes
//!
//! Tests leak_*, open_*, open_*_mut for individual fields, plus open/open_mut for full struct
//!
//! Struct has 7 fields: 512KB, 1MB, 2MB, 4MB, 8MB, 16MB, 32MB (total 63.5MB)

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use memcodec::Codec;
use memvault_derive::cipherbox;
use memzer::{DropSentinel, FastZeroizable, MemZer};

// Multi-field struct with 7 Vec<u8> fields (one per size)
#[cipherbox(DataCipherBox)]
#[derive(MemZer, Codec, Clone)]
#[memzer(drop)]
struct Data {
    field_512kb: Vec<u8>,
    field_1mb: Vec<u8>,
    field_2mb: Vec<u8>,
    field_4mb: Vec<u8>,
    field_8mb: Vec<u8>,
    field_16mb: Vec<u8>,
    field_32mb: Vec<u8>,
    #[codec(default)]
    __drop_sentinel: DropSentinel,
}

impl Default for Data {
    fn default() -> Self {
        Self {
            field_512kb: Vec::new(),
            field_1mb: Vec::new(),
            field_2mb: Vec::new(),
            field_4mb: Vec::new(),
            field_8mb: Vec::new(),
            field_16mb: Vec::new(),
            field_32mb: Vec::new(),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

fn bench_leak_field(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_leak_field");
    group.sample_size(100);

    // 512KB
    {
        let size = 512 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_512kb = vec![0xAA; size]).unwrap();
        group.bench_function("512KB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_512kb().unwrap();
                black_box(&*leaked);
            });
        });
    }

    // 1MB
    {
        let size = 1 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_1mb = vec![0xAA; size]).unwrap();
        group.bench_function("1MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_1mb().unwrap();
                black_box(&*leaked);
            });
        });
    }

    // 2MB
    {
        let size = 2 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_2mb = vec![0xAA; size]).unwrap();
        group.bench_function("2MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_2mb().unwrap();
                black_box(&*leaked);
            });
        });
    }

    // 4MB
    {
        let size = 4 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_4mb = vec![0xAA; size]).unwrap();
        group.bench_function("4MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_4mb().unwrap();
                black_box(&*leaked);
            });
        });
    }

    // 8MB
    {
        let size = 8 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_8mb = vec![0xAA; size]).unwrap();
        group.bench_function("8MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_8mb().unwrap();
                black_box(&*leaked);
            });
        });
    }

    // 16MB
    {
        let size = 16 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_16mb = vec![0xAA; size]).unwrap();
        group.bench_function("16MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_16mb().unwrap();
                black_box(&*leaked);
            });
        });
    }

    // 32MB
    {
        let size = 32 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_32mb = vec![0xAA; size]).unwrap();
        group.bench_function("32MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_32mb().unwrap();
                black_box(&*leaked);
            });
        });
    }

    group.finish();
}

fn bench_open_field(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_open_field");
    group.sample_size(100);

    // 512KB
    {
        let size = 512 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_512kb = vec![0xAA; size]).unwrap();
        group.bench_function("512KB", |b| {
            b.iter(|| {
                cb.open_field_512kb(|f| { black_box(f); }).unwrap();
            });
        });
    }

    // 1MB
    {
        let size = 1 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_1mb = vec![0xAA; size]).unwrap();
        group.bench_function("1MB", |b| {
            b.iter(|| {
                cb.open_field_1mb(|f| { black_box(f); }).unwrap();
            });
        });
    }

    // 2MB
    {
        let size = 2 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_2mb = vec![0xAA; size]).unwrap();
        group.bench_function("2MB", |b| {
            b.iter(|| {
                cb.open_field_2mb(|f| { black_box(f); }).unwrap();
            });
        });
    }

    // 4MB
    {
        let size = 4 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_4mb = vec![0xAA; size]).unwrap();
        group.bench_function("4MB", |b| {
            b.iter(|| {
                cb.open_field_4mb(|f| { black_box(f); }).unwrap();
            });
        });
    }

    // 8MB
    {
        let size = 8 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_8mb = vec![0xAA; size]).unwrap();
        group.bench_function("8MB", |b| {
            b.iter(|| {
                cb.open_field_8mb(|f| { black_box(f); }).unwrap();
            });
        });
    }

    // 16MB
    {
        let size = 16 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_16mb = vec![0xAA; size]).unwrap();
        group.bench_function("16MB", |b| {
            b.iter(|| {
                cb.open_field_16mb(|f| { black_box(f); }).unwrap();
            });
        });
    }

    // 32MB
    {
        let size = 32 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_32mb = vec![0xAA; size]).unwrap();
        group.bench_function("32MB", |b| {
            b.iter(|| {
                cb.open_field_32mb(|f| { black_box(f); }).unwrap();
            });
        });
    }

    group.finish();
}

fn bench_open_field_mut(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_open_field_mut");
    group.sample_size(100);

    // 512KB
    {
        let size = 512 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_512kb = vec![0xAA; size]).unwrap();
        group.bench_function("512KB", |b| {
            b.iter(|| {
                cb.open_field_512kb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .unwrap();
            });
        });
    }

    // 1MB
    {
        let size = 1 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_1mb = vec![0xAA; size]).unwrap();
        group.bench_function("1MB", |b| {
            b.iter(|| {
                cb.open_field_1mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .unwrap();
            });
        });
    }

    // 2MB
    {
        let size = 2 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_2mb = vec![0xAA; size]).unwrap();
        group.bench_function("2MB", |b| {
            b.iter(|| {
                cb.open_field_2mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .unwrap();
            });
        });
    }

    // 4MB
    {
        let size = 4 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_4mb = vec![0xAA; size]).unwrap();
        group.bench_function("4MB", |b| {
            b.iter(|| {
                cb.open_field_4mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .unwrap();
            });
        });
    }

    // 8MB
    {
        let size = 8 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_8mb = vec![0xAA; size]).unwrap();
        group.bench_function("8MB", |b| {
            b.iter(|| {
                cb.open_field_8mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .unwrap();
            });
        });
    }

    // 16MB
    {
        let size = 16 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_16mb = vec![0xAA; size]).unwrap();
        group.bench_function("16MB", |b| {
            b.iter(|| {
                cb.open_field_16mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .unwrap();
            });
        });
    }

    // 32MB
    {
        let size = 32 * 1024 * 1024;
        group.throughput(Throughput::Bytes(size as u64));
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| d.field_32mb = vec![0xAA; size]).unwrap();
        group.bench_function("32MB", |b| {
            b.iter(|| {
                cb.open_field_32mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .unwrap();
            });
        });
    }

    group.finish();
}

fn bench_open_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_open_full");
    group.sample_size(100);

    // Total: 512KB + 1MB + 2MB + 4MB + 8MB + 16MB + 32MB = 63.5MB
    let total_size = 512 * 1024 + 1024 * 1024 + 2 * 1024 * 1024 + 4 * 1024 * 1024
        + 8 * 1024 * 1024 + 16 * 1024 * 1024 + 32 * 1024 * 1024;
    group.throughput(Throughput::Bytes(total_size as u64));

    let mut cb = DataCipherBox::new();
    cb.open_mut(|d| {
        d.field_512kb = vec![0xAA; 512 * 1024];
        d.field_1mb = vec![0xBB; 1024 * 1024];
        d.field_2mb = vec![0xCC; 2 * 1024 * 1024];
        d.field_4mb = vec![0xDD; 4 * 1024 * 1024];
        d.field_8mb = vec![0xEE; 8 * 1024 * 1024];
        d.field_16mb = vec![0xFF; 16 * 1024 * 1024];
        d.field_32mb = vec![0x11; 32 * 1024 * 1024];
    })
    .unwrap();

    group.bench_function("all_fields_63.5MB", |b| {
        b.iter(|| {
            cb.open(|d| {
                black_box(&d.field_512kb);
                black_box(&d.field_1mb);
                black_box(&d.field_2mb);
                black_box(&d.field_4mb);
                black_box(&d.field_8mb);
                black_box(&d.field_16mb);
                black_box(&d.field_32mb);
            })
            .unwrap();
        });
    });

    group.finish();
}

fn bench_open_mut_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_open_mut_full");
    group.sample_size(100);

    // Total: 512KB + 1MB + 2MB + 4MB + 8MB + 16MB + 32MB = 63.5MB
    let total_size = 512 * 1024 + 1024 * 1024 + 2 * 1024 * 1024 + 4 * 1024 * 1024
        + 8 * 1024 * 1024 + 16 * 1024 * 1024 + 32 * 1024 * 1024;
    group.throughput(Throughput::Bytes(total_size as u64));

    let mut cb = DataCipherBox::new();
    cb.open_mut(|d| {
        d.field_512kb = vec![0xAA; 512 * 1024];
        d.field_1mb = vec![0xBB; 1024 * 1024];
        d.field_2mb = vec![0xCC; 2 * 1024 * 1024];
        d.field_4mb = vec![0xDD; 4 * 1024 * 1024];
        d.field_8mb = vec![0xEE; 8 * 1024 * 1024];
        d.field_16mb = vec![0xFF; 16 * 1024 * 1024];
        d.field_32mb = vec![0x11; 32 * 1024 * 1024];
    })
    .unwrap();

    group.bench_function("all_fields_63.5MB", |b| {
        b.iter(|| {
            cb.open_mut(|d| {
                d.field_512kb[0] = d.field_512kb[0].wrapping_add(1);
                d.field_1mb[0] = d.field_1mb[0].wrapping_add(1);
                d.field_2mb[0] = d.field_2mb[0].wrapping_add(1);
                d.field_4mb[0] = d.field_4mb[0].wrapping_add(1);
                d.field_8mb[0] = d.field_8mb[0].wrapping_add(1);
                d.field_16mb[0] = d.field_16mb[0].wrapping_add(1);
                d.field_32mb[0] = d.field_32mb[0].wrapping_add(1);
                black_box(&d);
            })
            .unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_leak_field,
    bench_open_field,
    bench_open_field_mut,
    bench_open_full,
    bench_open_mut_full,
);
criterion_main!(benches);
