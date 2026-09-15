// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Poly1305, the one-time authenticator of RFC 8439.
//!
//! One key authenticates one message. The key is a pair — `r`, which the
//! message is evaluated at, and `s`, which is added to the result — and a
//! second message under the same pair gives away the first.
//!
//! ## License
//!
//! GPL-3.0-only

#![no_std]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

mod backend;
mod consts;
mod poly1305;

#[cfg(test)]
mod tests;

pub use poly1305::{Poly1305, tag};

#[cfg(any(test, feature = "test-utils"))]
pub use backend::HAS_ASM;
