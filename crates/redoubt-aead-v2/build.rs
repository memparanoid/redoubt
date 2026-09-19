// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Whether AEGIS has any assembly to reach on this target.
//!
//! The condition is the one `redoubt-aead-aegis128l` compiles its own files
//! under, and it is written here rather than a second time in the library: a
//! `#[cfg(all(any(target_arch = ..), not(target_os = ..)))]` repeated at every
//! use is a list that drifts, and the drift is a target that links against
//! symbols nobody built.
//!
//! It says the symbols exist, not that the machine running the result has AES.
//! That question is the feature detector's and it is asked at run time.

/// What the crate compiles under where those symbols were built.
const HAS_AES_ASM: &str = "aes_asm";

fn main() {
    println!("cargo::rustc-check-cfg=cfg({HAS_AES_ASM})");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("cargo names the target architecture");
    let os = std::env::var("CARGO_CFG_TARGET_OS").expect("cargo names the target operating system");

    if os == "windows" {
        return;
    }

    if matches!(arch.as_str(), "x86_64" | "aarch64") {
        println!("cargo::rustc-cfg={HAS_AES_ASM}");
    }
}
