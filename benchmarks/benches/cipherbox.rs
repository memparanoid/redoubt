// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! CipherBox final benchmarks: per-field operations at various data sizes
//!
//! Tests leak_*, open_*, open_*_mut for individual fields, plus open/open_mut for full struct
//!
//! Struct has 7 fields: 512KB, 1MB, 2MB, 4MB, 8MB, 16MB, 32MB (total 63.5MB)

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use redoubt_codec::RedoubtCodec;
use redoubt_vault::cipherbox;
use redoubt_zero::{RedoubtZero, ZeroizeOnDropSentinel};

/// Multi-field struct with 7 Vec<u8> fields (one per size)
#[cipherbox(DataCipherBox)]
#[derive(Default, RedoubtZero, RedoubtCodec, Clone)]
#[fast_zeroize(drop)]
struct Data {
    field_512kb: Vec<u8>,
    field_1mb: Vec<u8>,
    field_2mb: Vec<u8>,
    field_4mb: Vec<u8>,
    field_8mb: Vec<u8>,
    field_16mb: Vec<u8>,
    field_32mb: Vec<u8>,
    #[codec(default)]
    __sentinel: ZeroizeOnDropSentinel,
}

fn bench_leak_field(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_leak_field");
    group.sample_size(100);

    // 512KB
    {
        let size = 512 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_512kb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_512kb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("512KB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_512kb().expect("failed to leak field_512kb");
                black_box(&*leaked);
            });
        });
    }

    // 1MB
    {
        let size = 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_1mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_1mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("1MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_1mb().expect("failed to leak field_1mb");
                black_box(&*leaked);
            });
        });
    }

    // 2MB
    {
        let size = 2 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_2mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_2mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("2MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_2mb().expect("failed to leak field_2mb");
                black_box(&*leaked);
            });
        });
    }

    // 4MB
    {
        let size = 4 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_4mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_4mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("4MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_4mb().expect("failed to leak field_4mb");
                black_box(&*leaked);
            });
        });
    }

    // 8MB
    {
        let size = 8 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_8mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_8mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("8MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_8mb().expect("failed to leak field_8mb");
                black_box(&*leaked);
            });
        });
    }

    // 16MB
    {
        let size = 16 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_16mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_16mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("16MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_16mb().expect("failed to leak field_16mb");
                black_box(&*leaked);
            });
        });
    }

    // 32MB
    {
        let size = 32 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_32mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_32mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("32MB", |b| {
            b.iter(|| {
                let leaked = cb.leak_field_32mb().expect("failed to leak field_32mb");
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
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_512kb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_512kb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("512KB", |b| {
            b.iter(|| {
                cb.open_field_512kb(|f| {
                    black_box(f);
                })
                .expect("failed to open_field_512kb");
            });
        });
    }

    // 1MB
    {
        let size = 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_1mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_1mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("1MB", |b| {
            b.iter(|| {
                cb.open_field_1mb(|f| {
                    black_box(f);
                })
                .expect("failed to open_field_1mb");
            });
        });
    }

    // 2MB
    {
        let size = 2 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_2mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_2mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("2MB", |b| {
            b.iter(|| {
                cb.open_field_2mb(|f| {
                    black_box(f);
                })
                .expect("failed to open_field_2mb");
            });
        });
    }

    // 4MB
    {
        let size = 4 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_4mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_4mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("4MB", |b| {
            b.iter(|| {
                cb.open_field_4mb(|f| {
                    black_box(f);
                })
                .expect("failed to open_field_4mb");
            });
        });
    }

    // 8MB
    {
        let size = 8 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_8mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_8mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("8MB", |b| {
            b.iter(|| {
                cb.open_field_8mb(|f| {
                    black_box(f);
                })
                .expect("failed to open_field_8mb");
            });
        });
    }

    // 16MB
    {
        let size = 16 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_16mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_16mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("16MB", |b| {
            b.iter(|| {
                cb.open_field_16mb(|f| {
                    black_box(f);
                })
                .expect("failed to open_field_16mb");
            });
        });
    }

    // 32MB
    {
        let size = 32 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_32mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_32mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("32MB", |b| {
            b.iter(|| {
                cb.open_field_32mb(|f| {
                    black_box(f);
                })
                .expect("failed to open_field_32mb");
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
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_512kb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_512kb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("512KB", |b| {
            b.iter(|| {
                cb.open_field_512kb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .expect("failed to open_field_512kb_mut");
            });
        });
    }

    // 1MB
    {
        let size = 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_1mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_1mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("1MB", |b| {
            b.iter(|| {
                cb.open_field_1mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .expect("failed to open_field_1mb_mut");
            });
        });
    }

    // 2MB
    {
        let size = 2 * 1024 * 1024;
        let mut cb = DataCipherBox::new();
        cb.open_mut(|d| {
            d.field_2mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_2mb");

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function("2MB", |b| {
            b.iter(|| {
                cb.open_field_2mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .expect("failed to open_field_2mb_mut");
            });
        });
    }

    // 4MB
    {
        let size = 4 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_4mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_4mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("4MB", |b| {
            b.iter(|| {
                cb.open_field_4mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .expect("failed to open_field_4mb_mut");
            });
        });
    }

    // 8MB
    {
        let size = 8 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_8mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_8mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("8MB", |b| {
            b.iter(|| {
                cb.open_field_8mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .expect("failed to open_field_8mb_mut");
            });
        });
    }

    // 16MB
    {
        let size = 16 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_16mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_16mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("16MB", |b| {
            b.iter(|| {
                cb.open_field_16mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .expect("failed to open_field_16mb_mut");
            });
        });
    }

    // 32MB
    {
        let size = 32 * 1024 * 1024;
        let mut cb = DataCipherBox::new();

        cb.open_mut(|d| {
            d.field_32mb = vec![0xAA; size];
            Ok(())
        })
        .expect("failed to open_mut field_32mb");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("32MB", |b| {
            b.iter(|| {
                cb.open_field_32mb_mut(|f| {
                    f[0] = f[0].wrapping_add(1);
                    black_box(f);
                })
                .expect("failed to open_field_32mb_mut");
            });
        });
    }

    group.finish();
}

fn bench_open_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_open_full");
    group.sample_size(100);

    // Total: 512KB + 1MB + 2MB + 4MB + 8MB + 16MB + 32MB = 63.5MB
    let total_size = 512 * 1024
        + 1024 * 1024
        + 2 * 1024 * 1024
        + 4 * 1024 * 1024
        + 8 * 1024 * 1024
        + 16 * 1024 * 1024
        + 32 * 1024 * 1024;
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
        Ok(())
    })
    .expect("failed to initialize all fields");

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
                Ok(())
            })
            .expect("failed to open all fields");
        });
    });

    group.finish();
}

fn bench_open_mut_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipherbox_open_mut_full");
    group.sample_size(100);

    // Total: 512KB + 1MB + 2MB + 4MB + 8MB + 16MB + 32MB = 63.5MB
    let total_size = 512 * 1024
        + 1024 * 1024
        + 2 * 1024 * 1024
        + 4 * 1024 * 1024
        + 8 * 1024 * 1024
        + 16 * 1024 * 1024
        + 32 * 1024 * 1024;
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
        Ok(())
    })
    .expect("failed to initialize all fields");

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
                Ok(())
            })
            .expect("failed to open_mut all fields");
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
