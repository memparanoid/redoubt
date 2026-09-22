// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Example: Minimal crypto wallet using Redoubt
//!
//! Demonstrates the four core Redoubt types:
//! - RedoubtArray: Fixed-size sensitive data (seed)
//! - RedoubtString: Variable-length strings (mnemonic)
//! - RedoubtVec: Variable-length bytes (encrypted backup)
//! - RedoubtSecret: Protected primitives (account index)

use redoubt::alloc::{RedoubtArray, RedoubtString, RedoubtVec};
use redoubt::codec::RedoubtCodec;
use redoubt::secret::RedoubtSecret;
use redoubt::vault::cipherbox;
use redoubt::zero::RedoubtZero;

// `testing_feature` names the feature the failure injection is gated on —
// `set_failure_mode` and `WalletBoxFailureMode`. The feature is read in this
// crate, so `Cargo.toml` is what turns it on, and what it carries is
// `redoubt/test-utils`, where the error the injection returns lives.
#[cipherbox(WalletBox, testing_feature = "test-utils")]
#[derive(Default, RedoubtCodec, RedoubtZero)]
pub struct Wallet {
    pub seed: RedoubtArray<u8, 32>,
    pub mnemonic: RedoubtString,
    pub backup: RedoubtVec<u8>,
    pub account_index: RedoubtSecret<u64>,
}
