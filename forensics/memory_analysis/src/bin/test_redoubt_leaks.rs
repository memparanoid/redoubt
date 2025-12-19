// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt::{
    FastZeroizable, RedoubtArray, RedoubtCodec, RedoubtString, RedoubtVec, RedoubtZero,
    ZeroizeOnDropSentinel, cipherbox, reset_master_key,
};

/// Calculate Shannon entropy in bits per byte
fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cipherbox(TestBox)]
#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct TestData {
    vec_data: RedoubtVec<u8>,
    string_data: RedoubtString,
    array_data: RedoubtArray<u8, 1024>,
}

#[derive(Clone, RedoubtZero)]
#[fast_zeroize(drop)]
struct Patterns {
    _padding: [u8; 1024],
    array_pattern: [u8; 1024],
    string_pattern: [u8; 1024],
    vec_pattern: [u8; 1024],
    __sentinel: ZeroizeOnDropSentinel,
}

impl Default for Patterns {
    fn default() -> Self {
        Self {
            _padding: [0u8; 1024],
            string_pattern: [0u8; 1024],
            array_pattern: [0u8; 1024],
            vec_pattern: [0u8; 1024],
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }
}

impl Patterns {
    fn fill(&mut self) {
        println!("[*] Creating hardcoded test patterns...");
        println!();

        self.vec_pattern = core::array::from_fn(|_| 0xAA);
        self.string_pattern = core::array::from_fn(|_| 0x41); // 'A' - valid ASCII/UTF-8
        self.array_pattern = core::array::from_fn(|_| 0xCC);

        println!("[+] Vec pattern: AAAA... (1024 bytes of 0xAA)");
        println!("[+] String pattern: AAAA... (1024 bytes of 0x41 'A')");
        println!("[+] Array pattern: CCCC... (1024 bytes of 0xCC)");
        println!();
    }
}

fn main() {
    {
        println!("[*] Redoubt Forensic Analysis - Sensitive Data Pattern Detection");
        println!("[*] Testing for sensitive data patterns in core dumps");
        println!();

        // Initialize cipherbox (generates master key)
        let mut test_box = TestBox::new();

        // Open TestBox to generate master key
        test_box
            .open_mut(|_| {})
            .expect("Failed to initialize TestBox");

        // Reset master key until it has sufficient entropy
        println!("[*] Searching for high-entropy master key...");
        const MIN_ENTROPY: f64 = 4.5;
        let mut attempts = 0;
        loop {
            attempts += 1;
            let mut key = redoubt::leak_master_key(32).expect("Failed to leak master key");
            let entropy = shannon_entropy(&key);

            println!("  Attempt {}: entropy = {:.3} bits/byte", attempts, entropy);

            if entropy >= MIN_ENTROPY {
                println!();
                println!(
                    "[+] Found high-entropy master key after {} attempts",
                    attempts
                );
                println!("[+] Master key entropy: {:.3} bits/byte", entropy);
                key.fast_zeroize();
                break;
            }

            key.fast_zeroize();
            reset_master_key();
        }
        println!();

        // Generate high-entropy patterns for RedoubtVec/String/Array
        println!("[*] Creating hardcoded test patterns...");
        println!();

        let mut patterns = Patterns::default();
        patterns.fill();

        println!("[+] Vec pattern: AAAA... (1024 bytes of 0xAA)");
        println!("[+] String pattern: BBBB... (1024 bytes of 0xBB)");
        println!("[+] Array pattern: CCCC... (1024 bytes of 0xCC)");
        println!();

        // Run 2 iterations to try to provoke leaks
        println!("[*] Running 2 iterations with pattern copies...");
        const ITERATIONS: usize = 20;

        for i in 0..ITERATIONS {
            test_box
                .open_mut(|data| {
                    let mut temp_patterns = Patterns::default();
                    temp_patterns.fill();

                    // Populate RedoubtVec
                    data.vec_data.clear();
                    data.vec_data
                        .extend_from_mut_slice(&mut temp_patterns.vec_pattern);

                    // Populate RedoubtString
                    data.string_data.clear();
                    let string_pattern = std::str::from_utf8(&temp_patterns.string_pattern)
                        .expect("String pattern should be valid UTF-8");
                    data.string_data.extend_from_str(string_pattern);

                    // Populate RedoubtArray using copy_from_slice
                    data.array_data
                        .as_mut_slice()
                        .copy_from_slice(&temp_patterns.array_pattern);

                    // Zeroize temporary clone
                    temp_patterns.fast_zeroize();
                })
                .expect("Failed to open cipherbox");

            if (i + 1) % 100 == 0 {
                println!("  Completed {} iterations...", i + 1);
            }
        }

        println!("[+] Completed {} iterations", ITERATIONS);
        println!();

        // Leak master key for Pattern #1
        let mut master_key = redoubt::leak_master_key(32).expect("Failed to leak master key");

        // Print patterns for script to capture - using encode_to_slice to avoid heap allocation
        print!("Pattern #1: ");
        for byte in master_key.as_slice() {
            print!("{:02x}", byte);
        }
        println!();

        print!("Pattern #2: ");
        for byte in &patterns.vec_pattern {
            print!("{:02x}", byte);
        }
        println!();

        print!("Pattern #3: ");
        for byte in &patterns.string_pattern {
            print!("{:02x}", byte);
        }
        println!();

        print!("Pattern #4: ");
        for byte in &patterns.array_pattern {
            print!("{:02x}", byte);
        }
        println!();
        println!();

        // Zeroize all patterns
        master_key.fast_zeroize();
        patterns.fast_zeroize();

        // Verify zeroization worked
        let vec_sum: u32 = patterns.vec_pattern.iter().map(|&b| b as u32).sum();
        let str_sum: u32 = patterns.string_pattern.iter().map(|&b| b as u32).sum();
        let arr_sum: u32 = patterns.array_pattern.iter().map(|&b| b as u32).sum();
        println!("[*] Post-zeroize verification:");
        println!("    vec_pattern sum: {} (should be 0)", vec_sum);
        println!("    string_pattern sum: {} (should be 0)", str_sum);
        println!("    array_pattern sum: {} (should be 0)", arr_sum);
        println!();

        // Signal to script that we're ready for dump
        println!("DUMP_NOW");
        println!();

        println!("[+] Patterns sent to script via stdout");
        println!("[*] Process is now ready for core dump analysis");
        println!("[*] PID: {}", std::process::id());
        println!(
            "[*] Sleeping indefinitely... (script will kill this process to generate core dump)"
        );
        println!();
    };

    // Sleep forever - script will kill us to generate core dump
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
