// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Build script for HKDF-SHA256 assembly implementations

fn main() {
    // Skip assembly compilation if pure-rust feature is enabled
    if std::env::var("CARGO_FEATURE_PURE_RUST").is_ok() {
        return;
    }

    // Get target platform info
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").ok();

    // Determine if we should compile assembly based on platform support
    // Must match the cfg conditions in src/lib.rs and src/hkdf.rs
    let should_compile_asm = match target_arch.as_str() {
        "aarch64" => {
            // AArch64: all platforms except WASM
            target_family.as_deref() != Some("wasm")
        }
        "x86_64" => {
            // x86_64: only Linux and macOS (not Windows, not WASM)
            matches!(target_os.as_str(), "linux" | "macos")
                && target_family.as_deref() != Some("wasm")
        }
        _ => false, // Other architectures use pure-rust fallback
    };

    if !should_compile_asm {
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
