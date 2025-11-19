// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests;

mod codec;
mod coerce;
mod decode;
mod encode;
mod error;
mod take;
mod traits;
mod types;
mod word_buf;
mod zeroizing_utils;

pub mod utils;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use codec::*;
pub use error::*;
pub use take::try_take_into;
pub use traits::*;
pub use types::*;
pub use word_buf::*;
