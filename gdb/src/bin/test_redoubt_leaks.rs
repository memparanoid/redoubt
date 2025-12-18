// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt::{
    cipherbox, leak_master_key, reset_master_key, FastZeroizable, RedoubtCodec, RedoubtVec,
    RedoubtZero, ZeroizationProbe,
};

#[cipherbox(TestBox)]
#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct TestData {
    field: [u8; 16],
}

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

fn main() {
    {
        println!("[*] Master Key Leak Detection Test");
        println!("[*] This test detects if getrandom leaves key material in memory");
        println!();

        // Initialize cipherbox (generates master key)
        let mut test_box = TestBox::new();

        // Open the box 1 million times to ensure leak is NOT from our open_mut
        // println!("[*] Opening cipherbox 1,000,000 times to test for leaks...");
        // for i in 0..100 {
        //     test_box
        //         .open_mut(|data| {
        //             data.field.copy_from_slice(&[0xAA; 16]);
        //         })
        //         .expect("Failed to open cipherbox");

        //     if (i + 1) % 100_000 == 0 {
        //         println!("  Completed {} iterations...", i + 1);
        //     }
        // }
        // println!("[+] Completed 1M iterations");

        // Enable core dumps AFTER cipherbox creation
        // (redoubt-guard disables them, but we need them for forensic analysis)

        const MIN_ENTROPY: f64 = 4.5;
        const MAX_ATTEMPTS: usize = 1000;

        println!("[*] Searching for high-entropy master key (>= {MIN_ENTROPY} bits/byte)...");

        // let mut attempts = 0;
        // let mut master_key = loop {
        //     attempts += 1;

        //     if attempts > MAX_ATTEMPTS {
        //         panic!("Failed to generate high-entropy key after {MAX_ATTEMPTS} attempts");
        //     }

        //     let mut key = leak_master_key(32).expect("Failed to leak master key");
        //     let entropy = shannon_entropy(&key);

        //     println!("  Attempt {attempts}: entropy = {entropy:.3} bits/byte");

        //     if entropy >= MIN_ENTROPY {
        //         println!();
        //         println!("[+] Found high-entropy key after {attempts} attempts");
        //         println!("[+] Master key entropy: {entropy:.3} bits/byte");
        //         break key;
        //     }

        //     key.fast_zeroize();

        //     // Reset and try again
        //     reset_master_key();
        // };
        //
        for i in 0..100 {
            test_box
                .open_mut(|data| {
                    data.field = [
                        44, 55, 66, 77, 88, 99, 11, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                    ];
                })
                .expect("Failed to open cipherbox");

            if (i + 1) % 100_000 == 0 {
                println!("  Completed {} iterations...", i + 1);
            }
        }

        #[cfg(target_os = "linux")]
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
        }

        let mut master_key = leak_master_key(32).expect("Failed to leak master key");

        // Print key in hex for script to capture
        println!();
        print!("KEY_HEX:");
        for byte in master_key.iter() {
            print!("{byte:02x}");
        }
        master_key.fast_zeroize();
        println!();
        println!();

        // Zeroize all key material
        master_key.fast_zeroize();

        // Signal to script that key is ready
        println!("KEY_READY:DEADBEEF");

        println!("[+] Key sent to script via stdout");

        // Signal to script that we're ready
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
