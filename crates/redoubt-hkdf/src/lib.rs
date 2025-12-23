// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA512 implementation with secure memory handling
//!
//! Implementation per RFC 5869 (HKDF) and RFC 6234 (SHA-512, HMAC).
//! Zero external dependencies. All intermediate values are zeroized.
//!
//! References:
//! - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//!   <https://datatracker.ietf.org/doc/html/rfc5869>
//! - RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
//!   <https://datatracker.ietf.org/doc/html/rfc6234>

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
mod tests;

#[cfg(all(
    not(feature = "pure-rust"),
    any(
        all(target_arch = "aarch64", not(target_family = "wasm")),
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "macos"),
            not(target_family = "wasm")
        )
    )
))]
mod asm;

mod error;
mod hkdf;

#[cfg(any(
    feature = "pure-rust",
    not(any(
        all(target_arch = "aarch64", not(target_family = "wasm")),
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "macos"),
            not(target_family = "wasm")
        )
    ))
))]
mod rust;

pub use error::HkdfError;
pub use hkdf::hkdf;
