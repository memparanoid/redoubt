// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    if target_arch != "aarch64" {
        return;
    }

    cc::Build::new()
        .file("src/asm/aegis_128l_aarch64.S")
        .flag("-march=armv8-a+crypto")
        .compile("aegis_asm");

    println!("cargo:rerun-if-changed=src/asm/aegis_128l_aarch64.S");
}
