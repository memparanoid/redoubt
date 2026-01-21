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
//! # Installation
//!
//! ```bash
//! cargo add redoubt --features full
//! ```
//!
//! Or in your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! redoubt = { version = "0.1.0-rc.2", features = ["full"] }
//! ```
//!
//! # Quick Start
//!
//! ```rust
//! use redoubt::alloc::{RedoubtArray, RedoubtString};
//! use redoubt::codec::RedoubtCodec;
//! use redoubt::secret::RedoubtSecret;
//! use redoubt::vault::cipherbox;
//! use redoubt::zero::RedoubtZero;
//!
//! #[cipherbox(Wallet)]
//! #[derive(Default, RedoubtCodec, RedoubtZero)]
//! struct WalletData {
//!     seed: RedoubtArray<u8, 32>,
//!     mnemonic: RedoubtString,
//!     counter: RedoubtSecret<u64>,
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut wallet = Wallet::new();
//!
//!     // Open the box and modify secrets
//!     wallet.open_mut(|w| {
//!         w.seed.replace_from_mut_array(&mut [0u8; 32]);
//!
//!         let mut mnemonic = String::from("abandon abandon ...");
//!         w.mnemonic.replace_from_mut_string(&mut mnemonic);
//!
//!         w.counter.replace(&mut 0u64);
//!
//!         Ok(())
//!     })?;
//!     // Box is re-encrypted here
//!
//!     // Read-only access
//!     wallet.open(|w| {
//!         let _ = w.counter.as_ref();
//!         Ok(())
//!     })?;
//!
//!     // Field-level access (decrypts only that field)
//!     wallet.open_counter_mut(|counter| {
//!         let mut next = *counter.as_ref() + 1;
//!         counter.replace(&mut next);
//!
//!         Ok(())
//!     })?;
//!
//!     // Leak to use outside closure scope
//!     {
//!         let seed = wallet.leak_seed()?;
//!         // use seed...
//!     } // seed is zeroized on drop
//!
//!     Ok(())
//! }
//! ```
//!
//! # API
//!
//! ## `open` / `open_mut`
//!
//! Access the entire decrypted struct. Re-encrypts when the closure returns:
//!
//! ```rust
//! # use redoubt::codec::RedoubtCodec;
//! # use redoubt::secret::RedoubtSecret;
//! # use redoubt::vault::cipherbox;
//! # use redoubt::zero::RedoubtZero;
//! # #[cipherbox(Wallet)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct WalletData { counter: RedoubtSecret<u64> }
//! # let mut wallet = Wallet::new();
//! wallet.open(|w| {
//!     // read-only access to all fields
//!     Ok(())
//! })?;
//!
//! wallet.open_mut(|w| {
//!     // read-write access to all fields
//!     Ok(())
//! })?;
//! # Ok::<(), redoubt::vault::CipherBoxError>(())
//! ```
//!
//! ## `open_<field>` / `open_<field>_mut`
//!
//! Access individual fields without decrypting the entire struct:
//!
//! ```rust
//! # use redoubt::alloc::RedoubtArray;
//! # use redoubt::codec::RedoubtCodec;
//! # use redoubt::vault::cipherbox;
//! # use redoubt::zero::RedoubtZero;
//! # #[cipherbox(Wallet)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct WalletData { seed: RedoubtArray<u8, 32> }
//! # let mut wallet = Wallet::new();
//! wallet.open_seed(|seed| {
//!     // read-only access to seed
//!     Ok(())
//! })?;
//!
//! wallet.open_seed_mut(|seed| {
//!     // read-write access to seed
//!     Ok(())
//! })?;
//! # Ok::<(), redoubt::vault::CipherBoxError>(())
//! ```
//!
//! ## `leak_<field>`
//!
//! Get a field value outside the closure. Returns a `ZeroizingGuard` that wipes memory on drop:
//!
//! ```rust
//! # use redoubt::alloc::RedoubtArray;
//! # use redoubt::codec::RedoubtCodec;
//! # use redoubt::vault::cipherbox;
//! # use redoubt::zero::RedoubtZero;
//! # #[cipherbox(Wallet)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct WalletData { seed: RedoubtArray<u8, 32> }
//! # let mut wallet = Wallet::new();
//! let seed = wallet.leak_seed()?;
//! // use seed...
//! // seed is zeroized when dropped
//! # Ok::<(), redoubt::vault::CipherBoxError>(())
//! ```
//!
//! ## Returning values
//!
//! Closures can return values. The return value is wrapped in a `ZeroizingGuard` that wipes memory on drop:
//!
//! ```rust
//! # use redoubt::codec::RedoubtCodec;
//! # use redoubt::secret::RedoubtSecret;
//! # use redoubt::vault::cipherbox;
//! # use redoubt::zero::RedoubtZero;
//! # #[cipherbox(Wallet)]
//! # #[derive(Default, RedoubtCodec, RedoubtZero)]
//! # struct WalletData { counter: RedoubtSecret<u64> }
//! # let mut wallet = Wallet::new();
//! let counter = wallet.open_counter_mut(|c| {
//!     let mut next = *c.as_ref() + 1;
//!     c.replace(&mut next);
//!
//!     Ok(next)
//! })?; // Returns Result<ZeroizingGuard<u64>, CipherBoxError>
//! // counter is zeroized when dropped
//! # Ok::<(), redoubt::vault::CipherBoxError>(())
//! ```
//!
//! # Types
//!
//! Redoubt provides secure containers for different use cases:
//!
//! ```rust
//! use redoubt::alloc::{RedoubtArray, RedoubtString, RedoubtVec};
//! use redoubt::secret::RedoubtSecret;
//!
//! // Fixed-size arrays (automatically zeroized on drop)
//! let mut api_key = RedoubtArray::<u8, 32>::new();
//! let mut signing_key = RedoubtArray::<u8, 64>::new();
//!
//! // Dynamic collections (zeroized on realloc and drop)
//! let mut tokens = RedoubtVec::<u8>::new();
//! let mut password = RedoubtString::new();
//!
//! // Primitives wrapped in Secret
//! let mut counter = RedoubtSecret::from(&mut 0u64);
//! let mut timestamp = RedoubtSecret::from(&mut 0i64);
//! ```
//!
//! ## When to use each type
//!
//! - **`RedoubtArray<T, N>`**: Fixed-size sensitive data (keys, hashes, seeds). Size known at compile time.
//! - **`RedoubtVec<T>`**: Variable-length byte arrays that may grow (encrypted tokens, variable-size keys).
//! - **`RedoubtString`**: Variable-length UTF-8 strings (passwords, mnemonics, API keys).
//! - **`RedoubtSecret<T>`**: Primitive types (u64, i32, bool) that need protection. Prevents accidental copies via controlled access.
//!
//! ## ⚠️ Critical: CipherBox fields MUST come from these types
//!
//! **All sensitive data in `#[cipherbox]` structs MUST ultimately come from: `RedoubtArray`, `RedoubtVec`, `RedoubtString`, or `RedoubtSecret`.**
//!
//! These types were forensically validated to leave no traces during the encryption-at-rest workflow.
//! You can compose them into nested structures, but the leaf values containing sensitive data must be these types.
//! Using standard types (`Vec<u8>`, `String`, `[u8; 32]`, `u64`) would leave unzeroized copies during encoding/decoding, defeating the security guarantees.
//!
//! ## How they prevent traces
//!
//! **`RedoubtVec` / `RedoubtString`**: Pre-zeroize old allocation before reallocation
//! - When capacity is exceeded, performs a safe 3-step reallocation:
//!   1. Copy data to temporary buffer
//!   2. Zeroize old allocation completely
//!   3. Allocate new buffer with 2x capacity and copy from temp (zeroizing temp)
//! - Safe methods: `extend_from_mut_slice`, `extend_from_mut_string` (zeroize source)
//! - **~40% performance penalty** for guaranteed security (double allocation during growth)
//! - Without this, standard `Vec`/`String` leave copies in abandoned allocations
//!
//! **`RedoubtArray`**: Prevents copies during assignment
//! - Simply redeclaring arrays (`let arr2 = arr1;`) can leave copies on stack
//! - `replace_from_mut_array` uses `ptr::swap_nonoverlapping` to exchange contents without intermediate copies
//! - Zeroizes the source after swap, ensuring no plaintext remains
//!
//! **`RedoubtSecret`**: Prevents accidental dereferencing of Copy types
//! - Forces explicit `as_ref()`/`as_mut()` calls to access the inner value
//! - Critical for primitives like `u64` which implement `Copy` and could silently duplicate if accessed directly
//!
//! ## Protections
//!
//! - All types implement `Debug` with **REDACTED** output (no accidental leaks in logs)
//! - **No `Copy` or `Clone`** traits (prevents unintended copies of sensitive data)
//! - Automatic zeroization on drop
//!
//! # Security
//!
//! - **Encryption at rest**: Sensitive data uses AEAD encryption (AEGIS-128L)
//! - **Guaranteed zeroization**: Memory is wiped using compiler barriers that prevent optimization
//! - **OS-level protections**: On Linux, the master key lives in a memory page protected by `prctl` and `mlock`, inaccessible to non-root memory dumps
//! - **Field-level encryption**: Decrypt only what you need, minimizing exposure time
//!
//! # Testing
//!
//! CipherBox generates failure injection methods for testing error handling:
//!
//! ```rust,ignore
//! #[cipherbox(WalletBox, testing_feature = "test-utils")]
//! struct Wallet { /* ... */ }
//!
//! // In tests:
//! let mut wallet = WalletBox::new();
//! wallet.set_failure_mode(WalletBoxFailureMode::FailOnNthOperation(2));
//!
//! assert!(wallet.open(|_| Ok(())).is_ok());  // 1st succeeds
//! assert!(wallet.open(|_| Ok(())).is_err()); // 2nd fails
//! ```
//!
//! - In the same crate, test utilities are always available under `#[cfg(test)]`
//! - For external crates, use `testing_feature` to export them conditionally
//!
//! See [examples/wallet/tests](https://github.com/memparanoid/redoubt/tree/main/examples/wallet/tests) for a complete example.
//!
//! # Platform support
//!
//! | Platform | Protection level |
//! |----------|------------------|
//! | Linux | Full (`prctl`, `rlimit`, `mlock`, `mprotect`) |
//! | macOS | Partial (`mlock`, `mprotect`) |
//! | Windows | Encryption only |
//! | WASI | Encryption only |
//! | `no_std` | Encryption only |
//!
//! # License
//!
//! GPL-3.0-only

#![cfg_attr(not(test), no_std)]

pub mod collections;
pub mod support;

pub use redoubt_aead as aead;
pub use redoubt_alloc as alloc;
pub use redoubt_codec as codec;
pub use redoubt_hkdf as hkdf;
pub use redoubt_rand as rand;
pub use redoubt_secret as secret;
pub use redoubt_vault as vault;
pub use redoubt_zero as zero;
