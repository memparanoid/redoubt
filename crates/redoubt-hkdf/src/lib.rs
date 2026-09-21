// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA256, RFC 5869.
//!
//! One function crosses out of here, and it holds nothing: key material goes in
//! and derived bytes land in storage the caller declared. What computes it is
//! the assembly where the target has it and the Rust where it does not, and
//! neither is a caller's decision.
//!
//! # What is inside and why
//!
//! The derivation is three standards stacked — the compression of FIPS 180-4,
//! the authenticator of RFC 2104, and RFC 5869 over both — and each of the
//! three is a seam of its own under `backend`. That is not decomposition for
//! its own sake: each has published answers, and a derivation that is wrong is
//! wrong in one of them.
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

mod backend;
mod consts;
mod error;
mod hkdf;

pub use error::HkdfError;
pub use hkdf::hkdf;
