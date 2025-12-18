// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Build script for AEGIS-128L assembly implementations

fn main() {
    // ARM64/AArch64 assembly implementation (Linux, macOS, Windows ARM64)
    #[cfg(target_arch = "aarch64")]
    {
        cc::Build::new()
            .file("src/aegis_asm/asm/aegis_128l_aarch64.S")
            .flag("-march=armv8-a+crypto")
            .compile("aegis_asm");

        println!("cargo:rerun-if-changed=src/aegis_asm/asm/aegis_128l_aarch64.S");
    }
}
