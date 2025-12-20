<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<p align="center"><em>Systematic encryption-at-rest for in-memory sensitive data in Rust.</em></p>

<p align="center">
    <a href="https://crates.io/crates/redoubt"><img src="https://img.shields.io/crates/v/redoubt.svg" alt="crates.io"></a>
    <a href="https://docs.rs/redoubt"><img src="https://docs.rs/redoubt/badge.svg" alt="docs.rs"></a>
    <a href="#"><img src="https://img.shields.io/badge/coverage-99.77%25-0ce500" alt="coverage"></a>
    <a href="#"><img src="https://img.shields.io/badge/vulnerabilities-0-brightgreen" alt="security"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-GPL--3.0--only-blue" alt="license"></a>
</p>

---

Redoubt is a Rust library for storing secrets in memory. Encrypted at rest, zeroized on drop, accessible only when you need them.

## Features

- ✨ **Zero boilerplate** — One macro, full protection
- 🔐 **Ephemeral decryption** — Secrets live encrypted, exist in plaintext only for the duration of access
- 🔒 **No surprises** — Allocation-free decryption with explicit zeroization on every path
- 🧹 **Automatic zeroization** — Memory is wiped when secrets go out of scope
- ⚡ **Amazingly fast** — Powered by AEGIS-128L encryption, bit-level encoding, and decrypt-only-what-you-need
- 🛡️ **OS-level protection** — Memory locking and protection against dumps
- 🎯 **Field-level access** — Decrypt only the field you need, not the entire struct
- 📦 **`no_std` compatible** — Works in embedded and WASI environments

## Installation
```toml
[dependencies]
redoubt = "0.1"
```

## Quick Start
```rust
use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, RedoubtArray, RedoubtString, Secret};

#[cipherbox(WalletBox)]
#[derive(Default, RedoubtCodec, RedoubtZero)]
struct Wallet {
    master_seed: RedoubtArray<u8, 64>,
    signing_key: RedoubtArray<u8, 32>,
    pin_hash: RedoubtArray<u8, 32>,
    mnemonic: RedoubtString,
    derivation_index: Secret<u64>,
}

fn main() {
    let mut wallet = WalletBox::new();

    // Store your secrets
    wallet.open_mut(|w| {
        let mut seed = derive_seed_from_mnemonic("abandon abandon ...");
        w.master_seed.replace_from_mut_array(&mut seed);

        let mut key = derive_signing_key(&w.master_seed);
        w.signing_key.replace_from_mut_array(&mut key);

        let mut hash = hash_pin("1234");
        w.pin_hash.replace_from_mut_array(&mut hash);

        w.mnemonic.extend_from_str("abandon abandon ...");

        let mut index = 0u64;
        w.derivation_index = Secret::from(&mut index);
    }).expect("Failed to initialize wallet");
    // `w` is encoded -> reencrypted

    // Leak secrets when needed outside closure scope
    {
        let seed: ZeroizingGuard<RedoubtArray<u8, 64>> = wallet
            .leak_master_seed()
            .expect("Failed to decrypt master seed");
        derive_child_keys(&seed);
    } // seed is zeroized on drop
}
```

## API

### Use `leak` methods to read your secrets

Use `leak_*` when you need the value outside the closure. Returns a `ZeroizingGuard` that wipes memory on drop:
```rust
let signing_key = wallet.leak_signing_key().expect("Failed to decrypt");

// Use signing_key normally
let signature = sign(&signing_key, message);

// signing_key is zeroized when it goes out of scope
```

### Modifying secrets

Use `open_mut` to modify secrets. Changes are re-encrypted when the closure returns:
```rust
wallet.open_mut(|w| {
    let mut new_hash = hash_pin(new_pin);
    w.pin_hash.replace_from_mut_array(&mut new_hash);
}).expect("Failed to decrypt wallet");
// `w` is encoded -> reencrypted
```

### Field-level access

Access individual fields without decrypting the entire struct. Method names are generated from your field names:
```rust
// Modify only the pin hash
wallet.open_pin_hash_mut(|hash| {
    let mut new_hash = hash_pin(new_pin);
    hash.replace_from_mut_array(&mut new_hash);
}).expect("Failed to decrypt pin_hash");
```

## Types

Redoubt provides secure containers for different use cases:

```rust
use redoubt::{Secret, RedoubtArray, RedoubtVec, RedoubtString};

// Fixed-size arrays (automatically zeroized on drop)
let mut api_key = RedoubtArray::<u8, 32>::new();
let mut signing_key = RedoubtArray::<u8, 64>::new();

// Dynamic collections (zeroized on realloc and drop)
let mut tokens = RedoubtVec::<u8>::new();
let mut password = RedoubtString::new();

// Primitives wrapped in Secret
let mut counter = Secret::from(&mut 0u64);
let mut timestamp = Secret::from(&mut 0i64);
```

### When to use each type:

- **`RedoubtArray<T, N>`**: Fixed-size arrays of bytes or primitives
- **`RedoubtVec<T>`**: Variable-length collections that may grow
- **`RedoubtString`**: Variable-length UTF-8 strings
- **`Secret<T>`**: Primitive types (u64, i32, etc.) that need protection

### How they prevent leaks:

- **`RedoubtVec` / `RedoubtString`**: Pre-zeroize old allocation before reallocation. Safe methods: `extend_from_mut_slice`, `extend_from_mut_string`. **~40% performance penalty** for guaranteed security.
- **`RedoubtArray`**: Redeclaring arrays can leave copies in memory. Use `replace_from_mut_array` to drain the source safely.

### Protections:

- All types implement `Debug` with **REDACTED** output (no accidental leaks in logs)
- **No `Copy` or `Clone`** traits (prevents unintended copies of sensitive data)
- Automatic zeroization on drop

## Security

- **Encryption at rest**: Sensitive data uses AEAD encryption (AEGIS-128L)
- **Guaranteed zeroization**: Memory is wiped using compiler barriers that prevent optimization
- **OS-level protections**: On Linux, the master key lives in a memory page protected by `prctl` and `mlock`, inaccessible to non-root memory dumps
- **Field-level encryption**: Decrypt only what you need, minimizing exposure time

### Forensic validation

Redoubt's zeroization guarantees are validated through memory dump analysis. We test that sensitive data from `RedoubtVec`, `RedoubtString`, `RedoubtArray`, and AEAD keys leave no traces in core dumps after being dropped or reallocated.

See [forensics/README.md](forensics/README.md) for detailed analysis results and testing methodology.

## Platform support

| Platform | Protection level |
|----------|------------------|
| Linux | Full (`prctl`, `rlimit`, `mlock`, `mprotect`) |
| macOS | Partial (`mlock`, `mprotect`) |
| Windows | Encryption only |
| WASI | Encryption only |
| `no_std` | Encryption only |

## Project Insights

For detailed information about testing methodology and other interesting technical details, see [INSIGHTS.md](INSIGHTS.md).

## Benchmarks

To run benchmarks:

```bash
cargo bench -p benchmarks --bench aegis128l
cargo bench -p benchmarks --bench alloc
cargo bench -p benchmarks --bench cipherbox
cargo bench -p benchmarks --bench codec
```

## License



This project is licensed under the [GNU General Public License v3.0-only](LICENSE).



