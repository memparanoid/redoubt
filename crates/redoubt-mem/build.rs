// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Assembles the copy for whichever architecture there is one for.
//!
//! Through `cc`, and not `global_asm!(include_str!(...))`, because the `.S`
//! files start with a `#if` that picks the object format and the symbol
//! spelling. A raw include hands the assembler the preprocessor directives
//! and it is the preprocessor that has to see them.

fn main() {
    println!("cargo:rerun-if-changed=asm/copy_x86_64.S");
    println!("cargo:rerun-if-changed=asm/copy_aarch64.S");

    let family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if !family.split(',').any(|one| one == "unix") {
        return;
    }

    let file = match arch.as_str() {
        "x86_64" => "asm/copy_x86_64.S",
        "aarch64" => "asm/copy_aarch64.S",
        _ => return,
    };

    cc::Build::new().file(file).compile("redoubt_copy");
}
