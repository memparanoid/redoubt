// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! <picture>
//!     <p align="center">
//!     <source media="(prefers-color-scheme: dark)" width="320" srcset="https://raw.githubusercontent.com/memparanoid/redoubt/main/logo_light.png">
//!     <source media="(prefers-color-scheme: light)" width="320" srcset="https://raw.githubusercontent.com/memparanoid/redoubt/main/logo_light.png">
//!     <img alt="Redoubt" width="320" src="https://raw.githubusercontent.com/memparanoid/redoubt/main/logo_light.png">
//!     </p>
//! </picture>
//!
//! <p align="center"><em>Systematic encryption-at-rest for in-memory sensitive data in Rust.</em></p>
//!
//! ---
//!
//! Redoubt is a Rust library for storing secrets in memory. Encrypted at rest, zeroized on drop, accessible only when you need them.
//!
//! # Features
//!
//! - ✨ **Zero boilerplate** — One macro, full protection
//! - 🔐 **Ephemeral decryption** — Secrets live encrypted, exist in plaintext only for the duration of access
//! - 🔒 **No surprises** — Allocation-free decryption with explicit zeroization on every path
//! - 🧹 **Automatic zeroization** — Memory is wiped when secrets go out of scope
//! - ⚡ **Amazingly fast** — Powered by AEGIS-128L encryption, bit-level encoding, and decrypt-only-what-you-need
//! - 🛡️ **OS-level protection** — Memory locking and protection against dumps
//! - 🎯 **Field-level access** — Decrypt only the field you need, not the entire struct
//! - 📦 **`no_std` compatible** — Works in embedded and WASI environments
//!
//! # Quick Start
//!
//! ```rust
//! use redoubt::{cipherbox, RedoubtArray, RedoubtCodec, RedoubtSecret, RedoubtString, RedoubtZero};
//! use redoubt_zero::FastZeroizable;
//!
//! #[cipherbox(WalletBox)]
//! #[derive(Default, RedoubtCodec, RedoubtZero)]
//! struct Wallet {
//!     master_seed: RedoubtArray<u8, 64>,
//!     signing_key: RedoubtArray<u8, 32>,
//!     pin_hash: RedoubtArray<u8, 32>,
//!     mnemonic: RedoubtString,
//!     derivation_index: RedoubtSecret<u64>,
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut wallet = WalletBox::new();
//!
//!     // Store your secrets
//!     wallet.open_mut(|w| {
//!         let mut seed = derive_seed_from_mnemonic("abandon abandon ...");
//!         w.master_seed.replace_from_mut_array(&mut seed);
//!
//!         let mut key = derive_signing_key(&w.master_seed);
//!         w.signing_key.replace_from_mut_array(&mut key);
//!
//!         let mut pin = [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//!                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//!         let mut hash = hash_pin(&mut pin);
//!         w.pin_hash.replace_from_mut_array(&mut hash);
//!
//!         w.mnemonic.extend_from_str("abandon abandon ...");
//!
//!         let mut index = 0u64;
//!         w.derivation_index = RedoubtSecret::from(&mut index);
//!
//!         Ok(())
//!     })?;
//!     // `w` is encoded -> reencrypted
//!
//!     // Leak secrets when needed outside closure scope
//!     {
//!         let seed = wallet.leak_master_seed()?;
//!         // Derive the next account key using the master seed
//!         let account_key = derive_account_key(&seed, 0)?;
//!         publish_account(&account_key)?;
//!     } // seed is zeroized on drop
//!
//!     Ok(())
//! }
//! # fn derive_seed_from_mnemonic(_: &str) -> [u8; 64] { [0u8; 64] }
//! # fn derive_signing_key(_: &RedoubtArray<u8, 64>) -> [u8; 32] { [0u8; 32] }
//! # fn hash_pin(pin: &mut [u8; 32]) -> [u8; 32] {
//! #     let hash = *pin;
//! #     pin.fast_zeroize();
//! #     hash
//! # }
//! # fn derive_account_key(_: &RedoubtArray<u8, 64>, _: u32) -> Result<[u8; 32], Box<dyn std::error::Error>> {
//! #     Ok([0u8; 32])
//! # }
//! # fn publish_account(_: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
//! ```
//!
//! # API Overview
//!
//! ## Reading secrets
//!
//! Use `open` to read your secrets. The closure receives an immutable reference:
//!
//! ```rust
//! # use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, RedoubtArray};
//! # #[cipherbox(WalletBox)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct Wallet { pin_hash: RedoubtArray<u8, 32> }
//! # let mut wallet = WalletBox::new();
//! # let user_input = "";
//! wallet.open(|w| {
//!     verify_pin(&w.pin_hash, user_input);
//!
//!     Ok(())
//! }).expect("Failed to decrypt");
//! # fn verify_pin(_: &RedoubtArray<u8, 32>, _: &str) {}
//! ```
//!
//! ## Modifying secrets
//!
//! Use `open_mut` to modify secrets. Changes are re-encrypted when the closure returns:
//!
//! ```rust
//! # use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, RedoubtArray};
//! # use redoubt_zero::FastZeroizable;
//! # #[cipherbox(WalletBox)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct Wallet { pin_hash: RedoubtArray<u8, 32> }
//! # let mut wallet = WalletBox::new();
//! # fn hash_pin(pin: &mut [u8; 32]) -> [u8; 32] {
//! #     let hash = *pin;
//! #     pin.fast_zeroize();
//! #     hash
//! # }
//! wallet.open_mut(|w| {
//!     let mut new_pin = [5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//!                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//!     let mut new_hash = hash_pin(&mut new_pin);
//!     w.pin_hash.replace_from_mut_array(&mut new_hash);
//!
//!     Ok(())
//! }).expect("Failed to decrypt wallet");
//! // `w` is encoded -> reencrypted
//! ```
//!
//! ## Returning values from callbacks
//!
//! Use callbacks to compute and return values while the data is decrypted:
//!
//! ```rust
//! # use redoubt::{cipherbox, RedoubtCodec, RedoubtSecret, RedoubtZero};
//! # #[cipherbox(WalletBox)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct Wallet { derivation_index: RedoubtSecret<u64> }
//! # let mut wallet = WalletBox::new();
//! // Return a value after modifying the wallet
//! let new_index = wallet.open_mut(|w| {
//!     let mut next = *w.derivation_index.as_ref() + 1;
//!     w.derivation_index.replace(&mut next);
//!
//!     Ok(next)
//! })?; // Returns Result<u64, CipherBoxError>
//! # Ok::<(), redoubt::CipherBoxError>(())
//! ```
//!
//! ## Field-level access
//!
//! Access individual fields without decrypting the entire struct. Method names are generated from your field names:
//!
//! ```rust
//! # use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, RedoubtArray};
//! # use redoubt_zero::FastZeroizable;
//! # #[cipherbox(WalletBox)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct Wallet { pin_hash: RedoubtArray<u8, 32> }
//! # let mut wallet = WalletBox::new();
//! # fn hash_pin(pin: &mut [u8; 32]) -> [u8; 32] {
//! #     let hash = *pin;
//! #     pin.fast_zeroize();
//! #     hash
//! # }
//! // Modify only the pin hash (no return value)
//! wallet.open_pin_hash_mut(|hash| {
//!     let mut new_pin = [5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//!                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//!     let mut new_hash = hash_pin(&mut new_pin);
//!     hash.replace_from_mut_array(&mut new_hash);
//!
//!     Ok(())
//! })?;
//!
//! // Return a value from field access
//! let is_valid = wallet.open_pin_hash(|hash| {
//!     let mut user_input = [5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//!                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//!     let mut entered = hash_pin(&mut user_input);
//!     let valid = hash.as_slice() == entered.as_slice();
//!     entered.fast_zeroize();
//!
//!     Ok(valid)
//! })?; // Returns Result<bool, CipherBoxError>
//! # Ok::<(), redoubt::CipherBoxError>(())
//! ```
//!
//! ## Leaking secrets
//!
//! Use `leak_*` when you need the value outside the closure. Returns a `ZeroizingGuard` that wipes memory on drop:
//!
//! ```rust
//! # use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, RedoubtSecret};
//! # #[cipherbox(WalletBox)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct Wallet { signing_key: RedoubtSecret<[u8; 32]> }
//! # let mut wallet = WalletBox::new();
//! let signing_key = wallet.leak_signing_key().expect("Failed to decrypt");
//!
//! // Use signing_key normally
//! let message = b"transaction data";
//! let signature = sign(&signing_key, message);
//!
//! // signing_key is zeroized when it goes out of scope
//! # fn sign(_: &RedoubtSecret<[u8; 32]>, _: &[u8]) -> [u8; 64] { [0u8; 64] }
//! ```
//!
//! # Types
//!
//! Redoubt provides secure containers for common types:
//!
//! ```rust
//! use redoubt::{RedoubtSecret, RedoubtVec, RedoubtString};
//!
//! // Fixed-size secrets
//! let api_key: RedoubtSecret<[u8; 32]> = RedoubtSecret::from(&mut [0u8; 32]);
//!
//! // Dynamic secrets (zeroized on realloc and drop)
//! let mut tokens: RedoubtSecret<RedoubtVec<u8>> = RedoubtSecret::from(&mut RedoubtVec::new());
//! let mut password: RedoubtSecret<RedoubtString> = RedoubtSecret::from(&mut RedoubtString::new());
//! ```
//!
//! `RedoubtVec` and `RedoubtString` automatically zeroize old memory when they grow,
//! preventing secret fragments from being left behind after reallocation.
//!
//! # Security
//!
//! - Sensitive data uses AEAD encryption at rest
//! - Memory is zeroized using barriers that prevent compiler optimization
//! - On Linux, Redoubt stores the master key in a memory page protected by `prctl` and `mlock`, inaccessible to non-root memory dumps
//! - Field-level encryption minimizes secret exposure time
//!
//! # Platform support
//!
//! | Platform | Protection level |
//! |----------|------------------|
//! | Linux | Full (`prctl`, `mlock`, `mprotect`) |
//! | macOS | Partial (`mlock`, `mprotect`) |
//! | Windows | Encryption only |
//! | WASI | Encryption only |
//! | `no_std` | Encryption only |
//!
//! ## License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]

pub mod collections;
pub mod support;

pub use redoubt_aead::*;
pub use redoubt_alloc::*;
pub use redoubt_codec::*;
pub use redoubt_secret::*;
pub use redoubt_vault::*;
pub use redoubt_zero::*;
