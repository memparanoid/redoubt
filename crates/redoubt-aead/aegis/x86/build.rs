// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_arch != "x86_64" || target_os == "windows" {
        return;
    }

    cc::Build::new()
        .file("src/asm/aegis_128l_x86_64.S")
        .flag("-maes")
        .compile("aegis_asm");

    println!("cargo:rerun-if-changed=src/asm/aegis_128l_x86_64.S");
}
