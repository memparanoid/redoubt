// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::hint::black_box;

#[cfg(feature = "internal-forensics")]
use redoubt::reset_master_key;
use redoubt::{FastZeroizable, ZeroizeOnDropSentinel};
use redoubt::{
    RedoubtArray, RedoubtCodec, RedoubtOption, RedoubtSecret, RedoubtString, RedoubtVec,
    RedoubtZero, cipherbox,
};

#[inline(never)]
fn use_u64_ref(val: &u64) {
    black_box(val);
}

#[cfg(feature = "internal-forensics")]
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
    redoubt_vec: RedoubtVec<u8>,
    redoubt_string: RedoubtString,
    redoubt_array: RedoubtArray<u8, 1024>,
    option_redoubt_vec: RedoubtOption<RedoubtVec<u8>>,
    option_redoubt_string: RedoubtOption<RedoubtString>,
    option_redoubt_array: RedoubtOption<RedoubtArray<u8, 1024>>,
    option_option_redoubt_string: RedoubtOption<RedoubtOption<RedoubtString>>,
    option_redoubt_secret_u64: RedoubtOption<RedoubtSecret<u64>>,
    redoubt_secret_u64: RedoubtSecret<u64>,
    read_write_secret: RedoubtSecret<u64>,
}

#[derive(Clone, RedoubtZero)]
#[fast_zeroize(drop)]
struct Patterns {
    pattern_1: [u8; 1024], // redoubt_vec
    pattern_2: [u8; 1024], // redoubt_string
    pattern_3: [u8; 1024], // redoubt_array
    pattern_4: [u8; 1024], // option_redoubt_vec
    pattern_5: [u8; 1024], // option_redoubt_string
    pattern_6: [u8; 1024], // option_redoubt_array
    pattern_7: [u8; 1024], // option_option_redoubt_string
    __sentinel: ZeroizeOnDropSentinel,
}

impl Default for Patterns {
    fn default() -> Self {
        Self {
            pattern_1: [0u8; 1024],
            pattern_2: [0u8; 1024],
            pattern_3: [0u8; 1024],
            pattern_4: [0u8; 1024],
            pattern_5: [0u8; 1024],
            pattern_6: [0u8; 1024],
            pattern_7: [0u8; 1024],
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }
}

impl Patterns {
    fn fill(&mut self) {
        self.pattern_1 = core::array::from_fn(|_| 0xAA); // redoubt_vec
        self.pattern_2 = core::array::from_fn(|_| 0x42); // redoubt_string - 'B'
        self.pattern_3 = core::array::from_fn(|_| 0xCC); // redoubt_array
        self.pattern_4 = core::array::from_fn(|_| 0xDD); // option_redoubt_vec
        self.pattern_5 = core::array::from_fn(|_| 0x45); // option_redoubt_string - 'E'
        self.pattern_6 = core::array::from_fn(|_| 0xFF); // option_redoubt_array
        self.pattern_7 = core::array::from_fn(|_| 0x47); // option_option_redoubt_string - 'G'
    }
}

#[derive(Clone, Default, RedoubtZero)]
#[fast_zeroize(drop)]
struct Values {
    value_1: u64, // redoubt_secret_u64
    value_2: u64, // option_redoubt_secret_u64 (RedoubtOption<RedoubtSecret<u64>>)
    value_3: u64, // read_write_secret
    __sentinel: ZeroizeOnDropSentinel,
}

impl Values {
    fn fill(&mut self) {
        self.value_1 = 0xDEADBEEFCAFEBABE; // redoubt_secret_u64
        self.value_2 = 0xCAFEBABEDEADBEEF; // option_redoubt_secret_u64
        self.value_3 = 0xABCDEF0123456789; // read_write_secret
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
            .open_mut(|_| Ok(()))
            .expect("Failed to initialize TestBox");

        #[cfg(feature = "internal-forensics")]
        {
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
        }

        // Generate test patterns and values
        println!("[*] Creating hardcoded test patterns and values...");
        println!();

        let mut patterns = Patterns::default();
        patterns.fill();

        let mut values = Values::default();
        values.fill();

        println!("[+] Pattern 1 (redoubt_vec): 1024 bytes of 0xAA");
        println!("[+] Pattern 2 (redoubt_string): 1024 bytes of 0x42 'B'");
        println!("[+] Pattern 3 (redoubt_array): 1024 bytes of 0xCC");
        println!("[+] Pattern 4 (option_redoubt_vec): 1024 bytes of 0xDD");
        println!("[+] Pattern 5 (option_redoubt_string): 1024 bytes of 0x45 'E'");
        println!("[+] Pattern 6 (option_redoubt_array): 1024 bytes of 0xFF");
        println!("[+] Pattern 7 (option_option_redoubt_string): 1024 bytes of 0x47 'G'");
        println!();
        println!("[+] Value 1 (redoubt_secret_u64): 0xDEADBEEFCAFEBABE");
        println!("[+] Value 2 (option_redoubt_secret_u64): 0xCAFEBABEDEADBEEF");
        println!("[+] Value 3 (read_write_secret): 0xABCDEF0123456789");
        println!();

        // Initialize read_write_secret before the loop
        println!("[*] Initializing read_write_secret field...");
        test_box
            .open_read_write_secret_mut(|secret| {
                secret.replace(&mut values.value_3);
                Ok(())
            })
            .expect("Failed to initialize read_write_secret");
        println!();

        // Run iterations to test for leaks
        const ITERATIONS: usize = 50;
        println!(
            "[*] Running {:?} iterations with pattern copies...",
            ITERATIONS
        );

        for i in 0..ITERATIONS {
            test_box
                .open_mut(|data| {
                    let mut temp_patterns = Patterns::default();
                    temp_patterns.fill();

                    let mut temp_values = Values::default();
                    temp_values.fill();

                    // Populate `redoubt_vec` field
                    data.redoubt_vec = RedoubtVec::from_mut_slice(&mut temp_patterns.pattern_1);

                    // Populate `redoubt_string` field
                    let string_pattern = std::str::from_utf8(&temp_patterns.pattern_2)
                        .expect("Pattern 2 should be valid UTF-8");
                    data.redoubt_string = RedoubtString::from_str(string_pattern);

                    // Populate `redoubt_array` field
                    data.redoubt_array = RedoubtArray::from_mut_array(&mut temp_patterns.pattern_3);

                    // Populate o`ption_redoubt_vec` field
                    data.option_redoubt_vec
                        .replace(&mut RedoubtVec::from_mut_slice(
                            &mut temp_patterns.pattern_4,
                        ));

                    // Populate `option_redoubt_string` field
                    let option_string_pattern = std::str::from_utf8(&temp_patterns.pattern_5)
                        .expect("Pattern 5 should be valid UTF-8");
                    data.option_redoubt_string
                        .replace(&mut RedoubtString::from_str(option_string_pattern));

                    // Populate `option_redoubt_array` field
                    data.option_redoubt_array
                        .replace(&mut RedoubtArray::from_mut_array(
                            &mut temp_patterns.pattern_6,
                        ));

                    // Populate `option_option_redoubt_string` field
                    let not_leaked_str_pattern = std::str::from_utf8(&temp_patterns.pattern_7)
                        .expect("Pattern 7 should be valid UTF-8");
                    let mut not_leaked_string = RedoubtString::from_str(not_leaked_str_pattern);
                    let mut not_leaked_option = RedoubtOption::default();
                    not_leaked_option.replace(&mut not_leaked_string);
                    data.option_option_redoubt_string
                        .replace(&mut not_leaked_option);

                    // Populate `option_redoubt_secret_u64` field
                    let mut leaked = RedoubtSecret::from(&mut temp_values.value_2);

                    // Force deref through as_ref() with black_box to prevent optimization
                    use_u64_ref(leaked.as_ref());

                    data.option_redoubt_secret_u64.replace(&mut leaked);

                    // Populate `redoubt_secret_u64` field
                    data.redoubt_secret_u64.replace(&mut temp_values.value_1);

                    // Force deref through as_ref() with black_box
                    use_u64_ref(data.redoubt_secret_u64.as_ref());

                    // Test read-write pattern on read_write_secret (simulates README example)
                    // Pattern: read with deref -> compute -> replace
                    let mut next = std::hint::black_box(*data.read_write_secret.as_ref());
                    data.read_write_secret.replace(&mut next); // Drains the copy

                    // Zeroize temporary clones
                    temp_patterns.fast_zeroize();
                    temp_values.fast_zeroize();

                    Ok(())
                })
                .expect("Failed to open cipherbox");

            if (i + 1) % 100 == 0 {
                println!("  Completed {} iterations...", i + 1);
            }
        }

        println!("[+] Completed {} iterations", ITERATIONS);
        println!();

        // Leak master key
        let mut master_key = redoubt::leak_master_key(32).expect("Failed to leak master key");

        // Print master key and patterns for script to capture
        print!("Master Key: ");
        for byte in master_key.as_slice() {
            print!("{:02x}", byte);
        }
        println!();

        // Print hardcoded pattern bytes (not full arrays)
        println!("Pattern #1: aa"); // `redoubt_vec` field pattern (1024 bytes of 0xAA)
        println!("Pattern #2: 42"); // `redoubt_string` field pattern (1024 bytes of 0x42 'B')
        println!("Pattern #3: cc"); // `redoubt_array` field pattern (1024 bytes of 0xCC)
        println!("Pattern #4: dd"); // `option_redoubt_vec` field pattern (1024 bytes of 0xDD)
        println!("Pattern #5: 45"); // `option_redoubt_string` field pattern (1024 bytes of 0x45 'E')
        println!("Pattern #6: ff"); // `option_redoubt_array` field pattern (1024 bytes of 0xFF)
        println!("Pattern #7: 47"); // `option_option_redoubt_string` field pattern (1024 bytes of 0x47 'G')
        println!();

        // Print secret values
        println!("Value #1: deadbeefcafebabe"); // `redoubt_secret_u64` field value
        println!("Value #2: cafebabedeadbeef"); // `option_redoubt_secret_u64` field value
        println!("Value #3: abcdef0123456789"); // `read_write_secret` field value
        println!();

        // Zeroize all patterns and values
        master_key.fast_zeroize();
        patterns.fast_zeroize();
        values.fast_zeroize();

        // Verify zeroization worked
        let sum1: u32 = patterns.pattern_1.iter().map(|&b| b as u32).sum();
        let sum2: u32 = patterns.pattern_2.iter().map(|&b| b as u32).sum();
        let sum3: u32 = patterns.pattern_3.iter().map(|&b| b as u32).sum();
        let sum4: u32 = patterns.pattern_4.iter().map(|&b| b as u32).sum();
        let sum5: u32 = patterns.pattern_5.iter().map(|&b| b as u32).sum();
        let sum6: u32 = patterns.pattern_6.iter().map(|&b| b as u32).sum();
        let sum7: u32 = patterns.pattern_7.iter().map(|&b| b as u32).sum();
        let val1: u64 = values.value_1;
        let val2: u64 = values.value_2;
        let val3: u64 = values.value_3;
        println!("[*] Post-zeroize verification:");
        println!("    pattern_1 sum: {} (should be 0)", sum1);
        println!("    pattern_2 sum: {} (should be 0)", sum2);
        println!("    pattern_3 sum: {} (should be 0)", sum3);
        println!("    pattern_4 sum: {} (should be 0)", sum4);
        println!("    pattern_5 sum: {} (should be 0)", sum5);
        println!("    pattern_6 sum: {} (should be 0)", sum6);
        println!("    pattern_7 sum: {} (should be 0)", sum7);
        println!("    value_1: {} (should be 0)", val1);
        println!("    value_2: {} (should be 0)", val2);
        println!("    value_3: {} (should be 0)", val3);
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
