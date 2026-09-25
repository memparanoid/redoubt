// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The assembly for the target, where there is one.
//!
//! Linux and Android only: the routine asks for the bytes by the Linux syscall
//! number. Every other target builds the crate as it is and asks the
//! `getrandom` crate.

const X86_64: &str = "src/asm/rand_x86_64.S";
const AARCH64: &str = "src/asm/rand_aarch64.S";

/// What the crate compiles under when they were built.
const HAS_ASM: &str = "rand_asm";

fn main() {
    println!("cargo::rustc-check-cfg=cfg({HAS_ASM})");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("cargo names the target architecture");
    let os = std::env::var("CARGO_CFG_TARGET_OS").expect("cargo names the target operating system");

    let Some(file) = for_target(&os, &arch) else {
        return;
    };

    cc::Build::new().file(file).compile("redoubt_rand_asm");

    println!("cargo::rerun-if-changed={file}");
    println!("cargo::rustc-cfg={HAS_ASM}");
}

fn for_target(os: &str, arch: &str) -> Option<&'static str> {
    if os != "linux" && os != "android" {
        return None;
    }

    match arch {
        "x86_64" => Some(X86_64),
        "aarch64" => Some(AARCH64),
        _ => None,
    }
}
