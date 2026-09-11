// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The codec against a payload the shape and size of a real one, rather than a
//! 2MB stress case.
//!
//! What travels in diakonos' negotiation is an artifact id and one presence bit
//! per chunk. The worst case the design admits is a 50GB artifact cut into
//! 512KB chunks: 102,400 chunks, so 12.5 KiB of bitset. Three orders of
//! magnitude under `codec.rs`, and small enough that per-call cost stops being
//! amortised away — which is the regime that decides whether the negotiation is
//! free or not.
//!
//! The output buffer is allocated **inside** the measured path, because that is
//! where it happens: each negotiation serialises once and sends, so no buffer
//! survives to be reused the way `CipherBox` reuses its `tmp_field_codec_buff`.
//! Hoisting it out would measure a flow this does not have.

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};

use redoubt_codec::{BytesRequired, Decode, Encode, RedoubtCodec, RedoubtCodecBuffer};

/// Chunk counts and the artifact each one stands for, at 512KB chunks:
/// 2GB, 12.5GB, 50GB, 200GB. The third is the worst case the design admits;
/// the fourth is there to show the curve past it.
const CHUNK_COUNTS: [usize; 4] = [4_096, 25_600, 102_400, 409_600];

#[derive(Clone, Default, RedoubtCodec)]
struct ChunkLayout {
    /// The artifact's sha256, as it is named on the wire.
    artifact_id: Vec<u8>,
    /// One bit per chunk: set means the node holds it.
    bitset: Vec<u8>,
}

impl ChunkLayout {
    /// A varied bit pattern, so nothing downstream can get lucky with an
    /// all-zero or all-one buffer.
    fn new(chunks: usize) -> Self {
        Self {
            artifact_id: vec![0xab; 32],
            bitset: (0..chunks.div_ceil(8)).map(|i| (i % 256) as u8).collect(),
        }
    }

    fn encoded_len(&self) -> usize {
        let mut data = self.clone();

        BytesRequired::encode_bytes_required(&mut data).expect("bytes required")
    }
}

fn configure(group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>) {
    group.measurement_time(std::time::Duration::from_secs(3));
    group.sample_size(100);
}

// === ENCODE ===

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("layout_encode");
    configure(&mut group);

    for chunks in CHUNK_COUNTS {
        let layout = ChunkLayout::new(chunks);
        group.throughput(Throughput::Bytes(layout.encoded_len() as u64));

        group.bench_with_input(BenchmarkId::new("encode", chunks), &layout, |b, l| {
            b.iter_batched(
                || l.clone(),
                |mut layout| {
                    let size =
                        BytesRequired::encode_bytes_required(&mut layout).expect("bytes required");
                    let mut buf = RedoubtCodecBuffer::with_capacity(size);

                    layout.encode_into(&mut buf).expect("encode");

                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// === DECODE ===

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("layout_decode");
    configure(&mut group);

    for chunks in CHUNK_COUNTS {
        let mut layout = ChunkLayout::new(chunks);
        let size = layout.encoded_len();

        let mut buf = RedoubtCodecBuffer::with_capacity(size);
        layout.encode_into(&mut buf).expect("encode");
        let encoded: Vec<u8> = buf.as_slice().to_vec();

        group.throughput(Throughput::Bytes(encoded.len() as u64));

        group.bench_with_input(BenchmarkId::new("decode", chunks), &encoded, |b, enc| {
            b.iter_batched(
                || enc.clone(),
                |mut bytes| {
                    let mut decoded = ChunkLayout::default();

                    decoded
                        .decode_from(&mut bytes.as_mut_slice())
                        .expect("decode");

                    black_box(decoded)
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// === ROUNDTRIP ===
//
// What a node pays per child: decode the layout that came up from it, and
// encode the folded answer to send further up. Buffer allocated inside, same as
// encode.

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("layout_roundtrip");
    configure(&mut group);

    for chunks in CHUNK_COUNTS {
        let layout = ChunkLayout::new(chunks);
        group.throughput(Throughput::Bytes(layout.encoded_len() as u64));

        group.bench_with_input(BenchmarkId::new("roundtrip", chunks), &layout, |b, l| {
            b.iter_batched(
                || l.clone(),
                |mut layout| {
                    let size =
                        BytesRequired::encode_bytes_required(&mut layout).expect("bytes required");
                    let mut buf = RedoubtCodecBuffer::with_capacity(size);

                    layout.encode_into(&mut buf).expect("encode");

                    let mut decoded = ChunkLayout::default();
                    let mut bytes = buf.as_mut_slice();
                    decoded.decode_from(&mut bytes).expect("decode");

                    black_box(decoded)
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode, bench_roundtrip);
criterion_main!(benches);
