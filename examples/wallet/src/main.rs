// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Example: Minimal crypto wallet using Redoubt
//
// Demonstrates the four core Redoubt types:
// - RedoubtArray: Fixed-size sensitive data (seed)
// - RedoubtString: Variable-length strings (mnemonic)
// - RedoubtVec: Variable-length bytes (encrypted backup)
// - RedoubtSecret: Protected primitives (account index)

use redoubt::alloc::{RedoubtArray, RedoubtString, RedoubtVec};
use redoubt::codec::RedoubtCodec;
use redoubt::secret::RedoubtSecret;
use redoubt::vault::cipherbox;
use redoubt::zero::RedoubtZero;

// testing_feature enables failure injection (set_failure_mode, WalletBoxFailureMode).
// In the same crate, test utilities are always available under #[cfg(test)].
// For external crates, gate with testing_feature to export them conditionally.
#[cipherbox(WalletBox, testing_feature = "test-utils")]
#[derive(Default, RedoubtCodec, RedoubtZero)]
struct Wallet {
    seed: RedoubtArray<u8, 32>,
    mnemonic: RedoubtString,
    backup: RedoubtVec<u8>,
    account_index: RedoubtSecret<u64>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = WalletBox::new();

    // Initialize wallet with secrets
    wallet.open_mut(|w| {
        // Seed from external source (e.g., derived from mnemonic)
        w.seed.replace_from_mut_array(&mut [0x42u8; 32]);

        // Store mnemonic phrase
        let mut mnemonic = String::from("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        w.mnemonic.replace_from_mut_string(&mut mnemonic);

        // Encrypted backup data
        w.backup.extend_from_mut_slice(&mut [0xAA; 64]);

        // Starting account index
        w.account_index.replace(&mut 0u64);

        Ok(())
    })?;

    println!("Wallet initialized");

    // Read-only access to full wallet
    wallet.open(|w| {
        assert_eq!(*w.account_index.as_ref(), 0);
        assert_eq!(w.mnemonic.len(), 93);
        assert_eq!(w.backup.len(), 64);

        println!("Current account index: {}", w.account_index.as_ref());
        println!("Mnemonic length: {} chars", w.mnemonic.len());
        println!("Backup size: {} bytes", w.backup.len());
        Ok(())
    })?;

    // Field-level mutation: increment account index
    let new_index = wallet.open_account_index_mut(|index| {
        let mut next = *index.as_ref() + 1;
        index.replace(&mut next);
        Ok(*index.as_ref())
    })?;

    assert_eq!(*new_index, 1);
    println!("New account index: {}", *new_index);

    // Leak seed for external use (e.g., key derivation)
    {
        let seed = wallet.leak_seed()?;
        assert_eq!(seed.as_slice()[0], 0x42);
        println!("Seed first byte: 0x{:02X}", seed.as_slice()[0]);
        // seed is zeroized when dropped
    }

    println!("Wallet operations complete");

    Ok(())
}
