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
//! <p align="center"><em>Systematic encryption-at-rest for sensitive data in Rust.</em></p>
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
//! use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, Secret};
//!
//! #[cipherbox(WalletBox)]
//! #[derive(Default, RedoubtCodec, RedoubtZero)]
//! struct Wallet {
//!     master_seed: Secret<[u8; 64]>,
//!     signing_key: Secret<[u8; 32]>,
//!     pin_hash: Secret<[u8; 32]>,
//! }
//!
//! fn main() {
//!     let mut wallet = WalletBox::new();
//!
//!     // Store your secrets
//!     wallet.open_mut(|w| {
//!         w.master_seed = Secret::new(derive_seed_from_mnemonic("abandon abandon ..."));
//!         w.signing_key = Secret::new(derive_signing_key(&w.master_seed));
//!         w.pin_hash = Secret::new(hash_pin("1234"));
//!     }).unwrap();
//!
//!     // Use them when needed
//!     wallet.open_signing_key(|key| {
//!         sign_transaction(key, &transaction);
//!     }).unwrap();
//!
//! }   // Everything zeroized, encryption keys gone
//! # fn derive_seed_from_mnemonic(_: &str) -> [u8; 64] { [0u8; 64] }
//! # fn derive_signing_key(_: &Secret<[u8; 64]>) -> [u8; 32] { [0u8; 32] }
//! # fn hash_pin(_: &str) -> [u8; 32] { [0u8; 32] }
//! # fn sign_transaction(_: &Secret<[u8; 32]>, _: &()) {}
//! # let transaction = ();
//! ```
//!
//! # API Overview
//!
//! ## Reading secrets
//!
//! Use `open` to read your secrets. The closure receives an immutable reference:
//!
//! ```rust
//! # use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, Secret};
//! # #[cipherbox(WalletBox)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct Wallet { pin_hash: Secret<[u8; 32]> }
//! # let mut wallet = WalletBox::new();
//! wallet.open(|w| {
//!     verify_pin(&w.pin_hash, user_input);
//! }).unwrap();
//! # fn verify_pin(_: &Secret<[u8; 32]>, _: &str) {}
//! # let user_input = "";
//! ```
//!
//! ## Modifying secrets
//!
//! Use `open_mut` to modify secrets. Changes are re-encrypted when the closure returns:
//!
//! ```rust
//! # use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, Secret};
//! # #[cipherbox(WalletBox)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct Wallet { pin_hash: Secret<[u8; 32]> }
//! # let mut wallet = WalletBox::new();
//! wallet.open_mut(|w| {
//!     w.pin_hash = Secret::new(hash_pin(new_pin));
//! }).unwrap();
//! # fn hash_pin(_: &str) -> [u8; 32] { [0u8; 32] }
//! # let new_pin = "";
//! ```
//!
//! ## Field-level access
//!
//! Access individual fields without decrypting the entire struct:
//!
//! ```rust
//! # use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, Secret};
//! # #[cipherbox(WalletBox)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct Wallet { signing_key: Secret<[u8; 32]>, pin_hash: Secret<[u8; 32]> }
//! # let mut wallet = WalletBox::new();
//! // Read only the signing key (other fields stay encrypted)
//! wallet.open_signing_key(|key| {
//!     sign_transaction(key, &tx);
//! }).unwrap();
//!
//! // Modify only the pin hash
//! wallet.open_pin_hash_mut(|hash| {
//!     *hash = Secret::new(hash_pin(new_pin));
//! }).unwrap();
//! # fn sign_transaction(_: &Secret<[u8; 32]>, _: &()) {}
//! # fn hash_pin(_: &str) -> [u8; 32] { [0u8; 32] }
//! # let tx = ();
//! # let new_pin = "";
//! ```
//!
//! ## Leaking secrets
//!
//! Use `leak_*` when you need the value outside the closure. Returns a `ZeroizingGuard` that wipes memory on drop:
//!
//! ```rust
//! # use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, Secret};
//! # #[cipherbox(WalletBox)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct Wallet { signing_key: Secret<[u8; 32]> }
//! # let mut wallet = WalletBox::new();
//! let signing_key = wallet.leak_signing_key().unwrap();
//!
//! // Use signing_key normally
//! let signature = sign(&signing_key, message);
//!
//! // signing_key is zeroized when it goes out of scope
//! # fn sign(_: &Secret<[u8; 32]>, _: &[u8]) -> [u8; 64] { [0u8; 64] }
//! # let message = b"";
//! ```
//!
//! # Types
//!
//! Redoubt provides secure containers for common types:
//!
//! ```rust
//! use redoubt::{Secret, RedoubtVec, RedoubtString};
//!
//! // Fixed-size secrets
//! let api_key: Secret<[u8; 32]> = Secret::new([0u8; 32]);
//!
//! // Dynamic secrets (zeroized on realloc and drop)
//! let mut tokens: Secret<RedoubtVec<u8>> = Secret::new(RedoubtVec::new());
//! let mut password: Secret<RedoubtString> = Secret::new(RedoubtString::new());
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

#![cfg_attr(not(test), no_std)]

pub mod collections;
pub mod support;

pub use redoubt_aead::*;
pub use redoubt_alloc::*;
pub use redoubt_codec::*;
pub use redoubt_vault::*;
pub use redoubt_zero::*;
