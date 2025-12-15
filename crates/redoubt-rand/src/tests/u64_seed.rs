// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::u64_seed::{get_entropy_u64, U64Seed};

#[test]
fn test_get_entropy_u64_succeeds() {
    // Happy path: should always succeed
    let result = get_entropy_u64();
    assert!(result.is_ok());
}

#[test]
fn test_u64_seed_drain_from() {
    let mut source = 0x1234567890ABCDEFu64;
    let mut seed = U64Seed::new();

    seed.drain_from(&mut source);

    assert_eq!(seed.expose(), 0x1234567890ABCDEF);
    assert_eq!(source, 0); // zeroized
}

#[test]
fn test_u64_seed_drain_from_bytes() {
    let mut bytes = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let mut seed = U64Seed::new();

    seed.drain_from_bytes(&mut bytes);

    assert_eq!(seed.expose(), 0xF0DEBC9A78563412u64); // little-endian
    assert_eq!(bytes, [0; 8]); // zeroized
}

#[test]
fn test_u64_seed_debug() {
    let mut seed = U64Seed::new();
    seed.generate().expect("Failed to generate seed");

    let debug_output = format!("{:?}", seed);
    assert_eq!(debug_output, "U64Seed([REDACTED])");
}

#[test]
fn test_u64_seed_default() {
    let seed = U64Seed::default();
    assert_eq!(seed.expose(), 0);
}

#[test]
#[ignore] // Run with: cargo test --release -- --ignored --nocapture
fn test_entropy_distribution() {
    // Statistical test: verify uniform distribution of entropy bytes
    // Extracts all 8 bytes from each u64 for 50M total samples
    const SAMPLES: usize = 6_250_000; // 6.25M × 8 bytes = 50M bytes
    const TOTAL_BYTES: usize = SAMPLES * 8;
    const EXPECTED_PER_VALUE: f64 = TOTAL_BYTES as f64 / 256.0; // ~195,312

    let mut counts = [0u32; 256];

    println!("Collecting {} samples ({} bytes)...", SAMPLES, TOTAL_BYTES);

    for _ in 0..SAMPLES {
        let seed = get_entropy_u64().expect("Failed to get entropy");

        // Extract all 8 bytes from the u64
        for i in 0..8 {
            let byte = ((seed >> (i * 8)) & 0xFF) as u8;
            counts[byte as usize] += 1;
        }
    }

    println!("Expected count per value: ~{:.0}", EXPECTED_PER_VALUE);

    // Chi-squared test for uniformity
    let mut chi_squared = 0.0;
    let mut min_count = u32::MAX;
    let mut max_count = 0u32;

    for &count in &counts {
        let observed = count as f64;
        let diff = observed - EXPECTED_PER_VALUE;
        chi_squared += (diff * diff) / EXPECTED_PER_VALUE;

        min_count = min_count.min(count);
        max_count = max_count.max(count);
    }

    println!("Chi-squared statistic: {:.2}", chi_squared);
    println!("Min count: {}, Max count: {}", min_count, max_count);
    println!(
        "Range: {:.2}% - {:.2}%",
        (min_count as f64 / EXPECTED_PER_VALUE) * 100.0,
        (max_count as f64 / EXPECTED_PER_VALUE) * 100.0
    );

    // Chi-squared critical value for df=255, p=0.001 is ~310.5
    // If our statistic is higher, distribution is likely non-uniform
    assert!(
        chi_squared < 350.0,
        "Chi-squared too high: {:.2} (distribution may not be uniform)",
        chi_squared
    );

    // Additional sanity check: no value should be wildly off
    // With 50M samples, allow ±7% deviation from expected (~31 standard deviations)
    let tolerance = EXPECTED_PER_VALUE * 0.07;
    for (value, &count) in counts.iter().enumerate() {
        let observed = count as f64;
        let deviation = (observed - EXPECTED_PER_VALUE).abs();
        assert!(
            deviation < tolerance,
            "Value {} appeared {} times (expected ~{:.0}, deviation {:.2})",
            value,
            count,
            EXPECTED_PER_VALUE,
            deviation
        );
    }

    println!("✓ Distribution test passed!");
}
