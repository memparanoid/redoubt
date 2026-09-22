// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Example: Minimal crypto wallet using Redoubt
//
// The box itself is in `lib.rs`, which is the shape a crate consuming Redoubt
// has: `tests/failure_injection.rs` opens the same one.

use wallet_example::WalletBox;

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
