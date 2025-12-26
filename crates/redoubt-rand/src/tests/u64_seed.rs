// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::u64_seed::generate;

#[test]
fn test_generate_succeeds() {
    let mut seed = 0u64;
    let result = unsafe { generate(&mut seed as *mut u64) };

    assert!(result.is_ok());
}

#[test]
fn test_entropy_distribution() {
    // Statistical test: verify hardware entropy is not catastrophically broken
    // Chi-squared minimum: 5 observations/category = 5×256 bytes = 160 samples
    // We use 10× minimum (1,600 samples) for more deterministic results
    const SAMPLES: usize = 1_600; // 1,600 × 8 bytes = 12,800 bytes (50 per value)
    const TOTAL_BYTES: usize = SAMPLES * 8;
    const EXPECTED_PER_VALUE: f64 = TOTAL_BYTES as f64 / 256.0; // = 50.0

    let mut counts = [0u32; 256];

    println!("Collecting {} samples ({} bytes)...", SAMPLES, TOTAL_BYTES);
    println!("Expected count per value: {:.0}", EXPECTED_PER_VALUE);

    for _ in 0..SAMPLES {
        let mut seed = 0u64;
        unsafe { generate(&mut seed as *mut u64).expect("Failed to get entropy") };

        // Extract all 8 bytes from the u64
        for i in 0..8 {
            let byte = ((seed >> (i * 8)) & 0xFF) as u8;
            counts[byte as usize] += 1;
        }
    }

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

    // Chi-squared critical value for df=255, p=0.001 is ~341
    // This only catches catastrophically broken hardware/implementations
    assert!(
        chi_squared < 350.0,
        "Chi-squared too high: {:.2} - hardware entropy may be severely broken",
        chi_squared
    );

    println!("✓ Hardware entropy smoke test passed!");
}
