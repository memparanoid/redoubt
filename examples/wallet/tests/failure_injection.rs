// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt::alloc::{RedoubtArray, RedoubtString, RedoubtVec};
use redoubt::codec::RedoubtCodec;
use redoubt::secret::RedoubtSecret;
use redoubt::vault::cipherbox;
use redoubt::zero::RedoubtZero;

#[cipherbox(WalletBox, testing_feature = "test-utils")]
#[derive(Default, RedoubtCodec, RedoubtZero)]
struct Wallet {
    seed: RedoubtArray<u8, 32>,
    mnemonic: RedoubtString,
    backup: RedoubtVec<u8>,
    account_index: RedoubtSecret<u64>,
}

#[test]
fn test_failure_injection() {
    // Failure injection works with all open methods:
    // open, open_mut, open_seed, open_seed_mut, leak_seed, etc.

    let mut wallet = WalletBox::new();

    // Fail on first call
    wallet.set_failure_mode(WalletBoxFailureMode::FailOnNthOperation(1));
    assert!(wallet.open(|_| Ok(())).is_err());

    // Fail on second call
    wallet.set_failure_mode(WalletBoxFailureMode::FailOnNthOperation(2));
    assert!(wallet.open(|_| Ok(())).is_ok()); // 1st succeeds
    assert!(wallet.open(|_| Ok(())).is_err()); // 2nd fails

    // Disable failure injection
    wallet.set_failure_mode(WalletBoxFailureMode::None);
    assert!(wallet.open(|_| Ok(())).is_ok());
}
