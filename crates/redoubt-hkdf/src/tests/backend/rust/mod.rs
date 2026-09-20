// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the Rust owes that no published answer covers.
//!
//! The standards say what a digest is and say nothing about what is left in
//! memory afterwards. Everything here is about that: a state carries key
//! material between its calls, and what it does with it when it is done is this
//! implementation's promise rather than FIPS 180-4's or RFC 2104's.
//!
//! The assembly makes the same promise a different way — it empties its
//! registers and its frame before each `ret` — so none of this is asked of the
//! seam. It is asked of the type that holds the bytes.

mod hkdf;
mod hmac;
mod sha256;
mod word32;
