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
use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, Secret};

#[cipherbox(WalletBox)]
#[derive(Default, RedoubtCodec, RedoubtZero)]
struct Wallet {
    master_seed: Secret<[u8; 64]>,
    signing_key: Secret<[u8; 32]>,
    pin_hash: Secret<[u8; 32]>,
}

fn main() {
    let mut wallet = WalletBox::new();

    // Store your secrets
    wallet.open_mut(|w| {
        w.master_seed = Secret::new(derive_seed_from_mnemonic("abandon abandon ..."));
        w.signing_key = Secret::new(derive_signing_key(&w.master_seed));
        w.pin_hash = Secret::new(hash_pin("1234"));
    }).unwrap();

    // Use them when needed
    wallet.open_signing_key(|key| {
        sign_transaction(key, &transaction);
    }).unwrap();
    
}   // Everything zeroized, encryption keys gone
```

## API

### Reading secrets

Use `open` to read your secrets. The closure receives an immutable reference:
```rust
wallet.open(|w| {
    verify_pin(&w.pin_hash, user_input);
}).unwrap();
```

### Modifying secrets

Use `open_mut` to modify secrets. Changes are re-encrypted when the closure returns:
```rust
wallet.open_mut(|w| {
    w.pin_hash = Secret::new(hash_pin(new_pin));
}).unwrap();
```

### Field-level access

Access individual fields without decrypting the entire struct. Method names are generated from your field names:
```rust
// Read only the signing key (other fields stay encrypted)
wallet.open_signing_key(|key| {
    sign_transaction(key, &tx);
}).unwrap();

// Modify only the pin hash
wallet.open_pin_hash_mut(|hash| {
    *hash = Secret::new(hash_pin(new_pin));
}).unwrap();
```

### Leaking secrets

Use `leak_*` when you need the value outside the closure. Returns a `ZeroizingGuard` that wipes memory on drop:
```rust
let signing_key = wallet.leak_signing_key().unwrap();

// Use signing_key normally
let signature = sign(&signing_key, message);

// signing_key is zeroized when it goes out of scope
```

## A realistic example
```rust
use redoubt::{cipherbox, RedoubtCodec, RedoubtZero, Secret, RedoubtVec, RedoubtString};

#[cipherbox(WalletSecretsBox)]
#[derive(Default, RedoubtCodec, RedoubtZero)]
struct WalletSecrets {
    /// BIP-39 seed (64 bytes from mnemonic)
    master_seed: Secret<[u8; 64]>,
    
    /// Ed25519 private key for signing transactions
    signing_key: Secret<[u8; 32]>,
    
    /// ChaCha20-Poly1305 key for encrypting local data
    encryption_key: Secret<[u8; 32]>,
    
    /// Argon2 hash of user's PIN
    pin_hash: Secret<[u8; 32]>,
    
    /// Recovery phrase (variable length)
    mnemonic: Secret<RedoubtString>,
    
    /// Additional key material
    key_material: Secret<RedoubtVec<u8>>,
}

struct Wallet {
    secrets: WalletSecretsBox,
    address: String,
}

impl Wallet {
    pub fn create(mnemonic: &str, pin: &str) -> Self {
        let mut secrets = WalletSecretsBox::new();
        
        secrets.open_mut(|s| {
            s.mnemonic = Secret::new(RedoubtString::from(mnemonic));
            s.master_seed = Secret::new(bip39::seed_from_mnemonic(mnemonic));
            s.signing_key = Secret::new(derive_signing_key(&s.master_seed));
            s.encryption_key = Secret::new(derive_encryption_key(&s.master_seed));
            s.pin_hash = Secret::new(argon2::hash(pin));
        }).expect("Failed to initialize wallet");
        
        let address = secrets.open_signing_key(|key| {
            derive_address(key)
        }).expect("Failed to derive address");
        
        Self { secrets, address }
    }
    
    pub fn sign_transaction(&mut self, tx: &Transaction, pin: &str) -> Result<Signature, Error> {
        // Verify PIN first (only decrypts pin_hash)
        self.secrets.open_pin_hash(|hash| {
            if !argon2::verify(pin, hash) {
                return Err(Error::InvalidPin);
            }
            Ok(())
        })??;
        
        // Sign transaction (only decrypts signing_key)
        self.secrets.open_signing_key(|key| {
            Ok(ed25519::sign(key, &tx.to_bytes()))
        })?
    }
    
    pub fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> Result<(), Error> {
        self.secrets.open_pin_hash_mut(|hash| {
            if !argon2::verify(old_pin, hash) {
                return Err(Error::InvalidPin);
            }
            *hash = Secret::new(argon2::hash(new_pin));
            Ok(())
        })?
    }
    
    pub fn export_encrypted_backup(&mut self) -> Result<Vec<u8>, Error> {
        // Leak encryption key for use with external crypto
        let key = self.secrets.leak_encryption_key()?;
        
        let backup_data = self.secrets.open(|s| {
            serialize_for_backup(s)
        })?;
        
        Ok(chacha20poly1305::encrypt(&key, &backup_data))
        // key is zeroized here
    }
}
```

## Types

Redoubt provides secure containers for common types:
```rust
use redoubt::{Secret, RedoubtVec, RedoubtString};

// Fixed-size secrets
let api_key: Secret<[u8; 32]> = Secret::new([0u8; 32]);

// Dynamic secrets (zeroized on realloc and drop)
let mut tokens: Secret<RedoubtVec<u8>> = Secret::new(RedoubtVec::new());
let mut password: Secret<RedoubtString> = Secret::new(RedoubtString::new());
```

`RedoubtVec` and `RedoubtString` automatically zeroize old memory when they grow, preventing secret fragments from being left behind after reallocation.

## Security

- Sensitive data uses AEAD encryption at rest
- Memory is zeroized using barriers that prevent compiler optimization
- On Linux, Redoubt stores the master key in a memory page protected by `prctl` and `mlock`, inaccessible to non-root memory dumps
- Field-level encryption minimizes secret exposure time

## Platform support

| Platform | Protection level |
|----------|------------------|
| Linux | Full (`prctl`, `mlock`, `mprotect`) |
| macOS | Partial (`mlock`, `mprotect`) |
| Windows | Encryption only |
| WASI | Encryption only |
| `no_std` | Encryption only |

## License



This project is licensed under the [GNU General Public License v3.0-only](LICENSE).



