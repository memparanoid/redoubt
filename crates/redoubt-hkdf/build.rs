// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Build script for HKDF-SHA256 assembly implementations

fn main() {
    // ARM64/AArch64 assembly implementation (Linux, macOS, Windows ARM64)
    // Uses base ARMv8-A without crypto extensions for maximum compatibility
    #[cfg(target_arch = "aarch64")]
    {
        cc::Build::new()
            .file("src/asm/hkdf_sha256_aarch64.S")
            .flag("-march=armv8-a")
            .compile("hkdf_sha256_asm");

        println!("cargo:rerun-if-changed=src/asm/hkdf_sha256_aarch64.S");
    }

    // x86_64 assembly implementation (Linux, macOS, Windows)
    // Uses baseline x86_64 without AVX2/SHA-NI for maximum compatibility
    #[cfg(target_arch = "x86_64")]
    {
        cc::Build::new()
            .file("src/asm/hkdf_sha256_x86_64.S")
            .compile("hkdf_sha256_asm");

        println!("cargo:rerun-if-changed=src/asm/hkdf_sha256_x86_64.S");
    }
}
