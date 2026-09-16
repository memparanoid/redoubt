// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The assembly for the target, where there is one.
//!
//! There is no portable fallback: AEGIS is the AES round function used as a
//! permutation, and written in Rust it would be a different algorithm with the
//! same name. A target this compiles nothing for is one whose binaries will not
//! find the symbols the crate calls, and the flag below is what says so.
//!
//! Windows is left out: the assembly is SysV and AAPCS, and Windows passes its
//! arguments in other registers.
//!
//! The flags say the assembler may emit AES instructions. They do not ask
//! whether the machine that runs the result has them, and nothing here does.

/// Where the file for each architecture is, relative to the manifest.
const X86_64: &str = "src/asm/aegis128l_x86_64.S";
const AARCH64: &str = "src/asm/aegis128l_aarch64.S";

/// What the crate compiles under when one of them was built.
const HAS_ASM: &str = "aegis128l_asm";

fn main() {
    println!("cargo::rustc-check-cfg=cfg({HAS_ASM})");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("cargo names the target architecture");
    let os = std::env::var("CARGO_CFG_TARGET_OS").expect("cargo names the target operating system");

    let Some((file, flag)) = for_target(&os, &arch) else {
        return;
    };

    cc::Build::new()
        .file(file)
        .flag(flag)
        .compile("aegis128l_asm");

    println!("cargo::rerun-if-changed={file}");
    println!("cargo::rustc-cfg={HAS_ASM}");
}

/// The file to compile and the flag that lets AES through, or nothing for a
/// target that has neither.
fn for_target(os: &str, arch: &str) -> Option<(&'static str, &'static str)> {
    if os == "windows" {
        return None;
    }

    match arch {
        "x86_64" => Some((X86_64, "-maes")),
        "aarch64" => Some((AARCH64, "-march=armv8-a+crypto")),
        _ => None,
    }
}
