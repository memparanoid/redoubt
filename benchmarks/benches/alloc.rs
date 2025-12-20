// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};

use redoubt_alloc::{RedoubtString, RedoubtVec};

// Fast mode: FAST_BENCH=1 cargo bench -p membench --bench alloc
fn is_fast_mode() -> bool {
    std::env::var("FAST_BENCH")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn configure_group(group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>) {
    if is_fast_mode() {
        group.measurement_time(std::time::Duration::from_millis(500));
        group.sample_size(10);
    } else {
        group.measurement_time(std::time::Duration::from_secs(3));
        group.sample_size(50);
    }
}

// =============================================================================
// Vec vs RedoubtVec
// =============================================================================

fn bench_vec_push_individual(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_push_individual");
    configure_group(&mut group);

    for size in [100, 1_000, 10_000, 100_000] {
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(BenchmarkId::new("Vec", size), &size, |b, &s| {
            b.iter(|| {
                let mut vec = Vec::new();
                for i in 0..s {
                    vec.push(i as u8);
                }
                black_box(vec)
            });
        });

        group.bench_with_input(BenchmarkId::new("RedoubtVec", size), &size, |b, &s| {
            b.iter(|| {
                let mut vec = RedoubtVec::new();
                let mut data: Vec<u8> = (0..s).map(|i| i as u8).collect();
                vec.extend_from_mut_slice(&mut data);
                black_box(vec)
            });
        });
    }

    group.finish();
}

fn bench_vec_push_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_push_only");
    configure_group(&mut group);

    for size in [100, 1_000, 10_000, 100_000] {
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(BenchmarkId::new("Vec", size), &size, |b, &s| {
            let mut vec = Vec::with_capacity(s);
            b.iter(|| {
                vec.clear();
                for i in 0..s {
                    vec.push(i as u8);
                }
                black_box(&vec);
            });
        });

        group.bench_with_input(BenchmarkId::new("RedoubtVec", size), &size, |b, &s| {
            let mut vec = RedoubtVec::with_capacity(s);
            b.iter(|| {
                vec.clear();
                let mut data: Vec<u8> = (0..s).map(|i| i as u8).collect();
                vec.extend_from_mut_slice(&mut data);
                black_box(&vec);
            });
        });
    }

    group.finish();
}

fn bench_vec_allocation_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_push_only_no_alloc");
    configure_group(&mut group);

    for size in [100, 1_000, 10_000, 100_000] {
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(BenchmarkId::new("Vec", size), &size, |b, &s| {
            let mut vec = Vec::<u8>::with_capacity(s);
            b.iter(|| {
                vec.clear();
                for i in 0..s {
                    vec.push(i as u8);
                }
                black_box(&vec);
            });
        });

        group.bench_with_input(BenchmarkId::new("RedoubtVec", size), &size, |b, &s| {
            let mut vec = RedoubtVec::<u8>::with_capacity(s);
            b.iter(|| {
                vec.clear();
                let mut data: Vec<u8> = (0..s).map(|i| i as u8).collect();
                vec.extend_from_mut_slice(&mut data);
                black_box(&vec);
            });
        });
    }

    group.finish();
}

fn bench_vec_drain_slice(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_drain_slice");
    configure_group(&mut group);

    for size in [100, 1_000, 10_000, 100_000] {
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(
            BenchmarkId::new("Vec::extend_from_slice", size),
            &size,
            |b, &s| {
                b.iter_batched(
                    || {
                        let source: Vec<u8> = (0..s).map(|i| i as u8).collect();
                        (Vec::new(), source)
                    },
                    |(mut vec, source)| {
                        vec.extend_from_slice(&source);
                        black_box(vec)
                    },
                    BatchSize::LargeInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("RedoubtVec::drain_slice", size),
            &size,
            |b, &s| {
                b.iter_batched(
                    || {
                        let source: Vec<u8> = (0..s).map(|i| i as u8).collect();
                        (RedoubtVec::new(), source)
                    },
                    |(mut vec, mut source)| {
                        vec.extend_from_mut_slice(&mut source);
                        black_box(vec)
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_vec_clear(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_clear");
    configure_group(&mut group);

    for size in [100, 1_000, 10_000, 100_000] {
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(BenchmarkId::new("Vec", size), &size, |b, &s| {
            b.iter_batched(
                || {
                    let mut vec = Vec::with_capacity(s);
                    for i in 0..s {
                        vec.push(i as u8);
                    }
                    vec
                },
                |mut vec| {
                    vec.clear();
                    black_box(vec)
                },
                BatchSize::LargeInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("RedoubtVec", size), &size, |b, &s| {
            b.iter_batched(
                || {
                    let mut vec = RedoubtVec::with_capacity(s);
                    let mut data: Vec<u8> = (0..s).map(|i| i as u8).collect();
                    vec.extend_from_mut_slice(&mut data);
                    vec
                },
                |mut vec| {
                    vec.clear();
                    black_box(vec)
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

// =============================================================================
// String vs RedoubtString
// =============================================================================

fn bench_string_copy_from_str(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_copy_from_str");
    configure_group(&mut group);

    let data_100 = "a".repeat(100);
    let data_1k = "a".repeat(1_000);
    let data_10k = "a".repeat(10_000);
    let data_100k = "a".repeat(100_000);

    for (name, data) in [
        ("100", &data_100),
        ("1k", &data_1k),
        ("10k", &data_10k),
        ("100k", &data_100k),
    ] {
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_with_input(BenchmarkId::new("String", name), data, |b, d| {
            b.iter(|| {
                let mut s = String::new();
                s.push_str(d);
                black_box(s)
            });
        });

        group.bench_with_input(BenchmarkId::new("RedoubtString", name), data, |b, d| {
            b.iter(|| {
                let mut s = RedoubtString::new();
                s.extend_from_str(d);
                black_box(s)
            });
        });
    }

    group.finish();
}

fn bench_string_with_capacity(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_with_capacity");
    configure_group(&mut group);

    let data_100 = "a".repeat(100);
    let data_1k = "a".repeat(1_000);
    let data_10k = "a".repeat(10_000);
    let data_100k = "a".repeat(100_000);

    for (name, data) in [
        ("100", &data_100),
        ("1k", &data_1k),
        ("10k", &data_10k),
        ("100k", &data_100k),
    ] {
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_with_input(BenchmarkId::new("String", name), data, |b, d| {
            b.iter(|| {
                let mut s = String::with_capacity(d.len());
                s.push_str(d);
                black_box(s)
            });
        });

        group.bench_with_input(BenchmarkId::new("RedoubtString", name), data, |b, d| {
            b.iter(|| {
                let mut s = RedoubtString::with_capacity(d.len());
                s.extend_from_str(d);
                black_box(s)
            });
        });
    }

    group.finish();
}

fn bench_string_drain_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_drain_string");
    configure_group(&mut group);

    let data_100 = "a".repeat(100);
    let data_1k = "a".repeat(1_000);
    let data_10k = "a".repeat(10_000);
    let data_100k = "a".repeat(100_000);

    for (name, data) in [
        ("100", &data_100),
        ("1k", &data_1k),
        ("10k", &data_10k),
        ("100k", &data_100k),
    ] {
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_with_input(BenchmarkId::new("RedoubtString", name), data, |b, d| {
            b.iter_batched(
                || (RedoubtString::new(), String::from(d.as_str())),
                |(mut s, mut source)| {
                    s.extend_from_mut_string(&mut source);
                    black_box(s)
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

fn bench_string_clear(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_clear");
    configure_group(&mut group);

    let data_100 = "a".repeat(100);
    let data_1k = "a".repeat(1_000);
    let data_10k = "a".repeat(10_000);
    let data_100k = "a".repeat(100_000);

    for (name, data) in [
        ("100", &data_100),
        ("1k", &data_1k),
        ("10k", &data_10k),
        ("100k", &data_100k),
    ] {
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_with_input(BenchmarkId::new("String", name), data, |b, d| {
            b.iter_batched(
                || {
                    let mut s = String::with_capacity(d.len());
                    s.push_str(d);
                    s
                },
                |mut s| {
                    s.clear();
                    black_box(s)
                },
                BatchSize::LargeInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("RedoubtString", name), data, |b, d| {
            b.iter_batched(
                || {
                    let mut s = RedoubtString::with_capacity(d.len());
                    s.extend_from_str(d);
                    s
                },
                |mut s| {
                    s.clear();
                    black_box(s)
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    vec_benches,
    bench_vec_allocation_only,
    bench_vec_push_only,
    bench_vec_push_individual,
    bench_vec_drain_slice,
    bench_vec_clear
);

criterion_group!(
    string_benches,
    bench_string_copy_from_str,
    bench_string_with_capacity,
    bench_string_drain_string,
    bench_string_clear
);

criterion_main!(vec_benches);
