// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Build script for HKDF-SHA256 assembly implementations

fn main() {
    // Declare custom cfg to suppress unexpected_cfgs warnings
    println!("cargo:rustc-check-cfg=cfg(is_asm_eligible)");

    // Skip assembly compilation if pure-rust feature is enabled
    if std::env::var("CARGO_FEATURE_PURE_RUST").is_ok() {
        return;
    }

    // Get target platform info
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    // Determine if assembly implementation is available for this platform
    // - aarch64: all OS (Linux, macOS, Windows, iOS, etc.)
    // - x86_64: only Linux/macOS (not Windows)
    let is_asm_eligible = match target_arch.as_str() {
        "aarch64" => true,
        "x86_64" => matches!(target_os.as_str(), "linux" | "macos"),
        _ => false,
    };

    // Set the cfg flag if eligible
    if is_asm_eligible {
        println!("cargo:rustc-cfg=is_asm_eligible");
    } else {
        println!("cargo:warning=Using pure-rust fallback for target: {}-{}", target_arch, target_os);
        return;
    }

    // Compile assembly for supported platforms
    match target_arch.as_str() {
        "aarch64" => {
            cc::Build::new()
                .file("src/asm/hkdf_sha256_aarch64.S")
                .flag("-march=armv8-a")
                .compile("hkdf_sha256_asm");

            println!("cargo:rerun-if-changed=src/asm/hkdf_sha256_aarch64.S");
        }
        "x86_64" => {
            cc::Build::new()
                .file("src/asm/hkdf_sha256_x86_64.S")
                .compile("hkdf_sha256_asm");

            println!("cargo:rerun-if-changed=src/asm/hkdf_sha256_x86_64.S");
        }
        _ => unreachable!(),
    }
}
