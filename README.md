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
use redoubt::{cipherbox, RedoubtArray, RedoubtCodec, RedoubtSecret, RedoubtString, RedoubtZero};

#[cipherbox(WalletBox)]
#[derive(Default, RedoubtCodec, RedoubtZero)]
struct Wallet {
    master_seed: RedoubtArray<u8, 64>,
    signing_key: RedoubtArray<u8, 32>,
    pin_hash: RedoubtArray<u8, 32>,
    mnemonic: RedoubtString,
    derivation_index: RedoubtSecret<u64>,
}

// Helper functions (stubs for example purposes)
use redoubt_zero::FastZeroizable;

fn derive_seed_from_mnemonic(_phrase: &str) -> [u8; 64] { [0u8; 64] }
fn derive_signing_key(_seed: &RedoubtArray<u8, 64>) -> [u8; 32] { [0u8; 32] }
fn hash_pin(pin: &mut [u8; 32]) -> [u8; 32] {
    let hash = *pin; // Compute hash (stub)
    pin.fast_zeroize(); // Don't forget to zeroize sensitive data
    hash
}
fn derive_account_key(_seed: &RedoubtArray<u8, 64>, _index: u32) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok([0u8; 32])
}
fn publish_account(_key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = WalletBox::new();

    // Store your secrets
    wallet.open_mut(|w| {
        let mut seed = derive_seed_from_mnemonic("abandon abandon ...");
        w.master_seed.replace_from_mut_array(&mut seed);

        let mut key = derive_signing_key(&w.master_seed);
        w.signing_key.replace_from_mut_array(&mut key);

        let mut pin = [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut hash = hash_pin(&mut pin);
        w.pin_hash.replace_from_mut_array(&mut hash);

        w.mnemonic.extend_from_str("abandon abandon ...");

        let mut index = 0u64;
        w.derivation_index = RedoubtSecret::from(&mut index);

        Ok(())
    })?;
    // `w` is encoded -> reencrypted

    // Leak secrets when needed outside closure scope
    {
        let seed = wallet.leak_master_seed()?;
        // Derive the next account key using the master seed
        let account_key = derive_account_key(&seed, 0)?;
        publish_account(&account_key)?;
    } // seed is zeroized on drop

    Ok(())
}
```

## API

### Use `leak` methods to read your secrets

Use `leak_*` when you need the value outside the closure. Returns a `ZeroizingGuard` that wipes memory on drop:
```rust
fn sign(_key: &RedoubtArray<u8, 32>, _message: &[u8]) -> [u8; 64] { [0u8; 64] }

let signing_key = wallet.leak_signing_key().expect("Failed to decrypt");

// Use signing_key normally
let message = b"transaction data";
let signature = sign(&signing_key, message);

// signing_key is zeroized when it goes out of scope
```

### Modifying secrets

Use `open_mut` to modify secrets. Changes are re-encrypted when the closure returns:
```rust
wallet.open_mut(|w| {
    let mut new_pin = [5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut new_hash = hash_pin(&mut new_pin);
    w.pin_hash.replace_from_mut_array(&mut new_hash);

    Ok(())
}).expect("Failed to decrypt wallet");
// `w` is encoded -> reencrypted
```

### Returning values from callbacks

Use callbacks to compute and return values while the data is decrypted:
```rust
// Return a value after modifying the wallet
let new_index = wallet.open_mut(|w| {
    let mut next = *w.derivation_index.as_ref() + 1;
    w.derivation_index.replace(&mut next);

    Ok(next)
})?; // Returns Result<u64, CipherBoxError>
```

### Field-level access

Access individual fields without decrypting the entire struct. Method names are generated from your field names:
```rust
// Modify only the pin hash (no return value)
wallet.open_pin_hash_mut(|hash| {
    let mut new_pin = [5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut new_hash = hash_pin(&mut new_pin);
    hash.replace_from_mut_array(&mut new_hash);

    Ok(())
})?;

// Return a value from field access
let is_valid = wallet.open_pin_hash(|hash| {
    let mut user_input = [5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut entered = hash_pin(&mut user_input);
    let valid = hash.as_slice() == entered.as_slice();
    entered.fast_zeroize();

    Ok(valid)
})?; // Returns Result<bool, CipherBoxError>
```


## Types

Redoubt provides secure containers for different use cases:

```rust
use redoubt::{RedoubtArray, RedoubtSecret, RedoubtString, RedoubtVec};

// Fixed-size arrays (automatically zeroized on drop)
let mut api_key = RedoubtArray::<u8, 32>::new();
let mut signing_key = RedoubtArray::<u8, 64>::new();

// Dynamic collections (zeroized on realloc and drop)
let mut tokens = RedoubtVec::<u8>::new();
let mut password = RedoubtString::new();

// Primitives wrapped in Secret
let mut counter = RedoubtSecret::from(&mut 0u64);
let mut timestamp = RedoubtSecret::from(&mut 0i64);
```

### When to use each type

- **`RedoubtArray<T, N>`**: Fixed-size sensitive data (keys, hashes, seeds). Size known at compile time.
- **`RedoubtVec<T>`**: Variable-length byte arrays that may grow (encrypted tokens, variable-size keys).
- **`RedoubtString`**: Variable-length UTF-8 strings (passwords, mnemonics, API keys).
- **`RedoubtSecret<T>`**: Primitive types (u64, i32, bool) that need protection. Prevents accidental copies via controlled access.

### ⚠️ Critical: CipherBox fields MUST come from these types

**All sensitive data in `#[cipherbox]` structs MUST ultimately come from: `RedoubtArray`, `RedoubtVec`, `RedoubtString`, or `RedoubtSecret`.**

These types were forensically validated (see [forensics/README.md](forensics/README.md)) to leave no traces during the encryption-at-rest workflow. You can compose them into nested structures, but the leaf values containing sensitive data must be these types. Using standard types (`Vec<u8>`, `String`, `[u8; 32]`, `u64`) would leave unzeroized copies during encoding/decoding, defeating the security guarantees.

### How they prevent traces

**`RedoubtVec` / `RedoubtString`**: Pre-zeroize old allocation before reallocation
- When capacity is exceeded, performs a safe 3-step reallocation:
  1. Copy data to temporary buffer
  2. Zeroize old allocation completely
  3. Allocate new buffer with 2x capacity and copy from temp (zeroizing temp)
- Safe methods: `extend_from_mut_slice`, `extend_from_mut_string` (zeroize source)
- **~40% performance penalty** for guaranteed security (double allocation during growth)
- Without this, standard `Vec`/`String` leave copies in abandoned allocations

**`RedoubtArray`**: Prevents copies during assignment
- Simply redeclaring arrays (`let arr2 = arr1;`) can leave copies on stack
- `replace_from_mut_array` uses `ptr::swap_nonoverlapping` to exchange contents without intermediate copies
- Zeroizes the source after swap, ensuring no plaintext remains

**`RedoubtSecret`**: Prevents accidental dereferencing of Copy types
- Forces explicit `as_ref()`/`as_mut()` calls to access the inner value
- Critical for primitives like `u64` which implement `Copy` and could silently duplicate if accessed directly

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



