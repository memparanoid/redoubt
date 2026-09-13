// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_arch != "aarch64" {
        return;
    }

    if !matches!(target_os.as_str(), "linux" | "macos") {
        println!(
            "cargo:warning=aarch64 assembly not supported on {}, skipping",
            target_os
        );
        return;
    }

    cc::Build::new()
        .file("src/asm/hkdf_sha256_aarch64.S")
        .flag("-march=armv8-a")
        .compile("hkdf_sha256_asm");

    println!("cargo:rerun-if-changed=src/asm/hkdf_sha256_aarch64.S");
}
