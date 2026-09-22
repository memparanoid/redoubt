// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use wallet_example::{WalletBox, WalletBoxFailureMode};

#[test]
fn test_failure_injection() {
    // Failure injection works with all open methods:
    // open, open_mut, open_seed, open_seed_mut, leak_seed, etc.

    let wallet = WalletBox::new();

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
