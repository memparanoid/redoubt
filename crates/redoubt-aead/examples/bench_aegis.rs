// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// // Casual benchmark for AEGIS-128L ARM64 assembly
// // Usage: cargo run --release --example bench_aegis

// #[cfg(target_arch = "aarch64")]
// use std::time::Instant;

// #[cfg(target_arch = "aarch64")]
// use redoubt_aead::aegis_asm::aead::{aegis128l_decrypt, aegis128l_encrypt};

// #[cfg(target_arch = "aarch64")]
// fn benchmark_size(size: usize, iterations: usize) {
//     let key = [0u8; 16];
//     let nonce = [0u8; 16];
//     let mut data = vec![0u8; size];
//     let mut tag = [0u8; 16];
//     let mut computed_tag = [0u8; 16];

//     // Warmup
//     for _ in 0..100 {
//         unsafe {
//             aegis128l_encrypt(
//                 &key,
//                 &nonce,
//                 std::ptr::null(),
//                 0,
//                 data.as_mut_ptr(),
//                 data.len(),
//                 &mut tag,
//             );
//             aegis128l_decrypt(
//                 &key,
//                 &nonce,
//                 std::ptr::null(),
//                 0,
//                 data.as_mut_ptr(),
//                 data.len(),
//                 &tag,
//                 &mut computed_tag,
//             );
//         }
//     }

//     // Benchmark ROUNDTRIP (encrypt + decrypt together)
//     let start = Instant::now();
//     for _ in 0..iterations {
//         unsafe {
//             aegis128l_encrypt(
//                 &key,
//                 &nonce,
//                 std::ptr::null(),
//                 0,
//                 data.as_mut_ptr(),
//                 data.len(),
//                 &mut tag,
//             );
//             aegis128l_decrypt(
//                 &key,
//                 &nonce,
//                 std::ptr::null(),
//                 0,
//                 data.as_mut_ptr(),
//                 data.len(),
//                 &tag,
//                 &mut computed_tag,
//             );
//         }
//     }
//     let roundtrip_duration = start.elapsed();

//     // We process the data twice per roundtrip (encrypt + decrypt)
//     let total_bytes = (size * iterations * 2) as f64;
//     let roundtrip_throughput = total_bytes / roundtrip_duration.as_secs_f64() / 1_000_000_000.0;

//     println!(
//         "{:>9} bytes: {:>7.2} GB/s ({:>10.2} ns/roundtrip)",
//         size,
//         roundtrip_throughput,
//         roundtrip_duration.as_nanos() as f64 / iterations as f64,
//     );
// }

// #[cfg(target_arch = "aarch64")]
// fn main() {
//     println!("AEGIS-128L ARM64 Assembly Benchmark");
//     println!("====================================");
//     println!();

//     // Different sizes with appropriate iteration counts
//     benchmark_size(16, 1_000_000); // 16 bytes (1 block)
//     benchmark_size(32, 1_000_000); // 32 bytes (2 blocks)
//     benchmark_size(64, 1_000_000); // 64 bytes
//     benchmark_size(256, 500_000); // 256 bytes
//     benchmark_size(1024, 200_000); // 1 KB
//     benchmark_size(4096, 100_000); // 4 KB
//     benchmark_size(16384, 50_000); // 16 KB
//     benchmark_size(32768, 25_000); // 32 KB
//     benchmark_size(65536, 10_000); // 64 KB
//     benchmark_size(131072, 5_000); // 128 KB
//     benchmark_size(262144, 2_500); // 256 KB
//     benchmark_size(524288, 1_000); // 512 KB
//     benchmark_size(1048576, 500); // 1 MB
//     benchmark_size(2097152, 250); // 2 MB
//     benchmark_size(4194304, 100); // 4 MB
//     benchmark_size(8388608, 50); // 8 MB
//     benchmark_size(16777216, 25); // 16 MB
//     benchmark_size(33554432, 10); // 32 MB
// }

// #[cfg(not(target_arch = "aarch64"))]
// fn main() {
//     println!("This benchmark only runs on aarch64 (ARM64)");
// }
fn main() {}
