// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Assembles the register capture for whichever architecture there is one for.

fn main() {
    println!("cargo:rerun-if-changed=asm/spiller_x86_64.S");
    println!("cargo:rerun-if-changed=asm/spiller_aarch64.S");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if os != "linux" {
        return;
    }

    let file = match arch.as_str() {
        "x86_64" => "asm/spiller_x86_64.S",
        "aarch64" => "asm/spiller_aarch64.S",
        _ => return,
    };

    cc::Build::new().file(file).compile("redoubt_spiller");
}
