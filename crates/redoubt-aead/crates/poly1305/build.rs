// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The assembly for the target, where there is one.
//!
//! A target with none builds the crate as it is and answers the same, from the
//! Rust the assembly was written against. What it does not get is the promise
//! the assembly is there for: that no value the compiler chose to spill sits in
//! a slot nothing wipes, and that what must not branch does not.
//!
//! Windows is left out of both: the assembly is SysV and AAPCS, and Windows
//! passes its arguments in other registers.

/// Where the file for each architecture is, relative to the manifest.
const X86_64: &str = "src/asm/poly1305_x86_64.S";
const AARCH64: &str = "src/asm/poly1305_aarch64.S";

/// What the crate compiles under when one of them was built.
const HAS_ASM: &str = "poly1305_asm";

fn main() {
    println!("cargo::rustc-check-cfg=cfg({HAS_ASM})");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("cargo names the target architecture");
    let os = std::env::var("CARGO_CFG_TARGET_OS").expect("cargo names the target operating system");

    let Some(file) = for_target(&os, &arch) else {
        return;
    };

    cc::Build::new().file(file).compile("poly1305_asm");

    println!("cargo::rerun-if-changed={file}");
    println!("cargo::rustc-cfg={HAS_ASM}");
}

/// The file to compile, or nothing for a target that has none.
fn for_target(os: &str, arch: &str) -> Option<&'static str> {
    if os == "windows" {
        return None;
    }

    match arch {
        "x86_64" => Some(X86_64),
        "aarch64" => Some(AARCH64),
        _ => None,
    }
}
