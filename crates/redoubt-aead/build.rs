// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

fn main() {
    // Declare custom cfg to suppress unexpected_cfgs warnings
    println!("cargo:rustc-check-cfg=cfg(is_aegis_asm_eligible)");

    // Skip assembly compilation if asm feature is not enabled
    if std::env::var("CARGO_FEATURE_ASM").is_err() {
        return;
    }

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    // Determine if AEGIS-128L assembly implementation is available for this platform
    // - aarch64: all OS (Linux, macOS, Windows, iOS, etc.)
    // - x86_64: only non-Windows (Linux, macOS, etc.) - Windows would need different asm syntax
    let is_aegis_asm_eligible = match target_arch.as_str() {
        "aarch64" => true,
        "x86_64" => target_os != "windows",
        _ => false,
    };

    if is_aegis_asm_eligible {
        println!("cargo:rustc-cfg=is_aegis_asm_eligible");

        // Compile assembly implementation
        match target_arch.as_str() {
            "aarch64" => {
                cc::Build::new()
                    .file("src/aegis_asm/asm/aegis_128l_aarch64.S")
                    .flag("-march=armv8-a+crypto")
                    .compile("aegis_asm");

                println!("cargo:rerun-if-changed=src/aegis_asm/asm/aegis_128l_aarch64.S");
            }
            "x86_64" => {
                cc::Build::new()
                    .file("src/aegis_asm/asm/aegis_128l_x86_64.S")
                    .flag("-maes")
                    .compile("aegis_asm");

                println!("cargo:rerun-if-changed=src/aegis_asm/asm/aegis_128l_x86_64.S");
            }
            _ => {}
        }
    }
}
