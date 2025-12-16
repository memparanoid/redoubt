// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::permutation::permute_with_seeds;
use crate::u64_seed::generate;

#[test]
#[ignore] // Run with: cargo test --release -- --ignored --nocapture
fn test_permutation_uniformity() {
    // Statistical test: verify that Fisher-Yates produces equiprobable permutations
    // 8 bytes = 8! = 40,320 possible permutations
    // Minimum samples = bins × 5 = 201,600. We use 2M for reliable chi-squared.

    const ARRAY_SIZE: usize = 8;
    const FACTORIAL_8: usize = 40_320;
    const SAMPLES: usize = 2_000_000;
    const EXPECTED_PER_PERM: f64 = SAMPLES as f64 / FACTORIAL_8 as f64; // ~49.6

    use std::collections::HashMap;

    let mut perm_counts: HashMap<[u8; ARRAY_SIZE], usize> = HashMap::new();

    println!("Collecting {} permutation samples...", SAMPLES);
    println!("Expected count per permutation: ~{:.1}", EXPECTED_PER_PERM);

    for i in 0..SAMPLES {
        if i % 500_000 == 0 && i > 0 {
            println!("Progress: {}/{} samples", i, SAMPLES);
        }

        let mut data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let mut seed_1 = 0u64;
        let mut seed_2 = 0u64;
        unsafe {
            generate(&mut seed_1 as *mut u64).expect("Failed to get entropy");
            generate(&mut seed_2 as *mut u64).expect("Failed to get entropy");
            permute_with_seeds(&mut data, &mut seed_1 as *mut u64, &mut seed_2 as *mut u64);
        }

        *perm_counts.entry(data).or_insert(0) += 1;
    }

    println!(
        "Unique permutations observed: {}/{}",
        perm_counts.len(),
        FACTORIAL_8
    );

    // Validate that all observed permutations are valid (contain unique elements 0-7)
    println!("Validating permutation integrity...");
    for (perm, &count) in &perm_counts {
        let mut sorted = *perm;
        sorted.sort();
        assert_eq!(
            sorted,
            [0u8, 1, 2, 3, 4, 5, 6, 7],
            "Invalid permutation {:?} appeared {} times",
            perm,
            count
        );
    }
    println!("✓ All permutations are valid (contain unique elements)");

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
    // We allow 5% deviation
    let chi_sq_lower = FACTORIAL_8 as f64 * 0.95; // 5% below expected
    let chi_sq_upper = FACTORIAL_8 as f64 * 1.05; // 5% above expected

    assert!(
        chi_squared >= chi_sq_lower && chi_squared <= chi_sq_upper,
        "Chi-squared {} outside acceptable range [{:.0}, {:.0}]",
        chi_squared,
        chi_sq_lower,
        chi_sq_upper
    );

    // Coverage check: with high sampling, we expect high coverage (>99%)
    let coverage = (perm_counts.len() as f64 / FACTORIAL_8 as f64) * 100.0;
    assert!(
        coverage > 99.0,
        "Coverage too low: {:.2}% (expected >99%)",
        coverage
    );

    println!("✓ Permutation uniformity test passed!");
}
