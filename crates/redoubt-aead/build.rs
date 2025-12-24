// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

fn main() {
    // Declare custom cfg to suppress unexpected_cfgs warnings
    println!("cargo:rustc-check-cfg=cfg(is_aegis_asm_eligible)");

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
    }
}
