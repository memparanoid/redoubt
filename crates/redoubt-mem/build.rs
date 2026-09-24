// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The assembly for the target, where there is one.
//!
//! A target with none builds the crate as it is and answers the same, from the
//! standard library's copy, swap and check. What it does not get is the promise
//! the assembly is there for: that none of the bytes are left in a register.
//!
//! Windows is left out: the assembly is SysV and AAPCS, and Windows passes its
//! arguments in other registers.
//!
//! Through `cc`, and not `global_asm!(include_str!(...))`, because the `.S`
//! files start with a `#if` that picks the object format and the symbol
//! spelling, and it is the preprocessor that has to see it.

/// The files for each architecture, relative to the manifest.
const X86_64: [&str; 3] = [
    "asm/copy_x86_64.S",
    "asm/swap_x86_64.S",
    "asm/utf8_x86_64.S",
];
const AARCH64: [&str; 3] = [
    "asm/copy_aarch64.S",
    "asm/swap_aarch64.S",
    "asm/utf8_aarch64.S",
];

/// What the crate compiles under when they were built.
const HAS_ASM: &str = "mem_asm";

fn main() {
    println!("cargo::rustc-check-cfg=cfg({HAS_ASM})");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("cargo names the target architecture");
    let os = std::env::var("CARGO_CFG_TARGET_OS").expect("cargo names the target operating system");

    let Some(files) = for_target(&os, &arch) else {
        return;
    };

    cc::Build::new().files(files).compile("redoubt_mem_asm");

    for file in files {
        println!("cargo::rerun-if-changed={file}");
    }

    println!("cargo::rustc-cfg={HAS_ASM}");
}

/// The files to compile, or nothing for a target that has none.
fn for_target(os: &str, arch: &str) -> Option<[&'static str; 3]> {
    if os == "windows" {
        return None;
    }

    match arch {
        "x86_64" => Some(X86_64),
        "aarch64" => Some(AARCH64),
        _ => None,
    }
}
