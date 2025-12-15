// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::permutation::{double_permute, permute_with_seed};
use crate::u64::U64;
use crate::u64_seed::generate;

#[test]
fn test_permute_with_seed_changes_data() {
    let mut data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let original = data;

    permute_with_seed(&mut data, 0x1234567890ABCDEF);

    // Data should be permuted
    assert_ne!(data, original);

    // All elements should still be present (just reordered)
    let mut sorted = data;
    sorted.sort();
    assert_eq!(sorted, original);
}

#[test]
fn test_permute_with_seed_is_deterministic() {
    let mut data1 = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut data2 = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let seed = 0x1234567890ABCDEF;

    permute_with_seed(&mut data1, seed);
    permute_with_seed(&mut data2, seed);

    assert_eq!(data1, data2);
}

#[test]
fn test_permute_with_seed_different_seeds_produce_different_results() {
    let mut data1 = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut data2 = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    permute_with_seed(&mut data1, 0x1111111111111111);
    permute_with_seed(&mut data2, 0x2222222222222222);

    assert_ne!(data1, data2);
}

#[test]
fn test_permute_empty_slice() {
    let mut data: [u8; 0] = [];
    permute_with_seed(&mut data, 0x1234567890ABCDEF);
    // Should not panic
}

#[test]
fn test_permute_single_element() {
    let mut data = [42u8];
    permute_with_seed(&mut data, 0x1234567890ABCDEF);
    assert_eq!(data, [42u8]);
}

#[test]
#[should_panic(expected = "xorshift64 seed cannot be zero")]
fn test_permute_with_zero_seed_panics() {
    let mut data = [0u8, 1, 2, 3];
    permute_with_seed(&mut data, 0);
}

#[test]
fn test_double_permute_32_bytes() {
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let original = key;

    let mut seed1 = U64::new();
    let mut seed2 = U64::new();
    generate(&mut seed1).expect("Failed to generate seed1");
    generate(&mut seed2).expect("Failed to generate seed2");

    double_permute(&mut key, &mut seed1, &mut seed2);

    // Key should be permuted
    assert_ne!(key, original);

    // All elements should still be present
    let mut sorted = key;
    sorted.sort();
    assert_eq!(sorted, original);
}

#[test]
fn test_permute_large_key() {
    let mut key = [0u8; 256];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    permute_with_seed(&mut key, 0xDEADBEEFCAFEBABE);

    // Verify it's a valid permutation (all values preserved)
    let mut counts = [0usize; 256];
    for &byte in &key {
        counts[byte as usize] += 1;
    }

    // Each value 0-255 should appear exactly once
    for (value, &count) in counts.iter().enumerate() {
        assert_eq!(count, 1, "Value {} appeared {} times", value, count);
    }
}

#[test]
#[ignore] // Run with: cargo test --release -- --ignored --nocapture
fn test_permutation_uniformity() {
    // Statistical test: verify that Fisher-Yates produces equiprobable permutations
    // 8 bytes = 8! = 40,320 possible permutations
    // We'll sample many permutations and verify uniform distribution

    const ARRAY_SIZE: usize = 8;
    const FACTORIAL_8: usize = 40_320;
    const SAMPLES: usize = 4_032_000; // 100x the number of permutations
    const EXPECTED_PER_PERM: f64 = SAMPLES as f64 / FACTORIAL_8 as f64; // ~100

    use std::collections::HashMap;

    let mut perm_counts: HashMap<[u8; ARRAY_SIZE], usize> = HashMap::new();

    println!("Collecting {} permutation samples...", SAMPLES);
    println!("Expected count per permutation: ~{:.1}", EXPECTED_PER_PERM);

    for i in 0..SAMPLES {
        if i % 500_000 == 0 && i > 0 {
            println!("Progress: {}/{} samples", i, SAMPLES);
        }

        let mut data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let seed = crate::u64_seed::get_entropy_u64().expect("Failed to get entropy");

        permute_with_seed(&mut data, seed);

        *perm_counts.entry(data).or_insert(0) += 1;
    }

    println!("Unique permutations observed: {}/{}", perm_counts.len(), FACTORIAL_8);

    // Calculate chi-squared statistic
    let mut chi_squared = 0.0;
    let mut min_count = usize::MAX;
    let mut max_count = 0usize;

    for &count in perm_counts.values() {
        let observed = count as f64;
        let diff = observed - EXPECTED_PER_PERM;
        chi_squared += (diff * diff) / EXPECTED_PER_PERM;

        min_count = min_count.min(count);
        max_count = max_count.max(count);
    }

    println!("Chi-squared statistic: {:.2}", chi_squared);
    println!("Min count: {}, Max count: {}", min_count, max_count);
    println!(
        "Range: {:.2}% - {:.2}%",
        (min_count as f64 / EXPECTED_PER_PERM) * 100.0,
        (max_count as f64 / EXPECTED_PER_PERM) * 100.0
    );

    // Chi-squared test with df=40319
    // For a uniform distribution, chi-squared should be close to df
    // We allow some deviation, but not too much
    let chi_sq_lower = FACTORIAL_8 as f64 * 0.95; // 5% below expected
    let chi_sq_upper = FACTORIAL_8 as f64 * 1.05; // 5% above expected

    assert!(
        chi_squared >= chi_sq_lower && chi_squared <= chi_sq_upper,
        "Chi-squared {} outside acceptable range [{:.0}, {:.0}]",
        chi_squared,
        chi_sq_lower,
        chi_sq_upper
    );

    // Coverage check: with 100x sampling, we expect high coverage (>99%)
    let coverage = (perm_counts.len() as f64 / FACTORIAL_8 as f64) * 100.0;
    assert!(
        coverage > 99.0,
        "Coverage too low: {:.2}% (expected >99%)",
        coverage
    );

    // Check individual permutation counts are within acceptable range
    // We allow ±2% deviation (stricter than entropy test which had <1% range)
    let tolerance = EXPECTED_PER_PERM * 0.02;
    let min_allowed = (EXPECTED_PER_PERM - tolerance) as usize; // 98
    let max_allowed = (EXPECTED_PER_PERM + tolerance) as usize; // 102

    assert!(
        min_count >= min_allowed,
        "Min count {} below threshold {} (±2% tolerance, expected ~{:.0})",
        min_count,
        min_allowed,
        EXPECTED_PER_PERM
    );

    assert!(
        max_count <= max_allowed,
        "Max count {} exceeds threshold {} (±2% tolerance, expected ~{:.0})",
        max_count,
        max_allowed,
        EXPECTED_PER_PERM
    );

    println!("✓ Permutation uniformity test passed!");
}
