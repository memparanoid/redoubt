// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

# CipherBox Design Documentation

## Overview

`CipherBox` provides encrypted storage for sensitive data structures with automatic zeroization guarantees. This document explains the design decisions and data flow patterns.

## Core Design Principles

### 1. In-Place Decryption/Encryption

All cryptographic operations are **in-place** and **destructive**:
- `decrypt` drains ciphertext → plaintext (ciphertext becomes zeros)
- `encode`/`decode` drain buffers (source becomes zeros)
- This enables efficient zeroization without explicit cleanup

### 2. Two Access Patterns

#### Pattern A: `open`/`open_mut` (Full Struct Access)

```rust
pub fn open<F>(&mut self, f: F) -> Result<(), CipherBoxError>
where
    F: Fn(&T)
```

**Flow**:
1. `decrypt_struct(&master_key)` → **DRAINS** `ciphertexts[]` into `value`
2. Callback `f(&value)` executes
3. `encrypt_struct(&master_key, &mut value)` → **RE-ENCRYPTS** back to `ciphertexts[]`

**Why decrypt → encrypt?**
Because `decrypt_struct` is destructive (drains ciphertexts to zeros), we MUST re-encrypt to restore the encrypted state. Without re-encryption, the ciphertexts would be lost.

**Why this seems wasteful?**
It's not! The alternative would be duplicating all logic between `open` (read-only) and `open_mut` (read-write). Since `open` is rarely used in practice (most code uses `leak_field` for reads), the overhead is acceptable for code simplicity.

#### Pattern B: `leak_field`/`open_field` (Single Field Access)

```rust
pub fn leak_field<Field, const M: usize>(&mut self) -> Result<ZeroizingGuard<Field>, CipherBoxError>
```

**Flow**:
1. `decrypt_field` → **CLONES** `ciphertexts[M]` into `tmp_field_cyphertext` (line 192)
2. Decrypt operates on the temporary copy (line 197)
3. `decode_from` drains `tmp_field_cyphertext` (line 202)
4. Return `field` (original `ciphertexts[M]` remains intact)

**Why clone?**
Cloning allows us to:
- Return the field by ownership (no re-encryption needed)
- Keep the original ciphertext intact for future accesses
- Extremely efficient for single-field operations (most common use case)

**Why leak is efficient?**
The clone is small (single field), decrypt happens on the copy, and we avoid the full struct decrypt → encrypt cycle.

## Memory Safety Guarantees

### Temporary Buffer Zeroization

The `tmp_field_cyphertext` buffer is guaranteed to be zeroized in all paths:

**Happy path**: `decode_from` drains the buffer (design guarantee)
**Error path**: Explicit zeroization in error handlers

**Tests**:
- `test_decrypt_field_ok` (happy path)
- `test_decrypt_field_propagates_decode_error` (error path)

Both verify `is_vec_fully_zeroized(tmp)` after operations.

### Callback Error Safety

**CRITICAL DESIGN DECISION**: Callbacks CANNOT return `Result`.

**Why?**
1. Callbacks execute **after** decrypt (data is already in plaintext)
2. If callback fails mid-execution, data may be partially modified
3. We have NO saved state to rollback to (ciphertexts were drained)
4. Re-encrypting corrupted state → data loss
5. Not re-encrypting → plaintext memory leak

**Correct pattern for fallible operations**:

```rust
// 1. Leak the data (makes a copy, ciphertext stays intact)
let data = wallet_box.leak_master_seed()?;

// 2. Perform fallible operation (data is outside the box)
let new_seed = derive_new_seed(&data, passphrase)?;

// 3. Commit when ready (atomic update)
wallet_box.open_master_seed_mut(|seed| {
    seed.drain_from_slice(&new_seed);  // Will zeroize new_seed
})?;
```

This pattern ensures:
- Operations can fail safely (data is leaked, not decrypted in-place)
- Original encrypted data remains untouched until commit
- Commit is atomic (callback cannot fail, only crypto operations)

## Implementation Notes

### Field Access Methods

```rust
try_decrypt_field<F, const M: usize>  // Lines 183-205
decrypt_field<F, const M: usize>      // Lines 207-224
try_encrypt_field<F, const M: usize>  // Lines 227-263
encrypt_field<F, const M: usize>      // Lines 266-285
```

All field operations use const generic `M` for compile-time field index verification.

### Struct Access Methods

```rust
encrypt_struct  // Lines 128-141
decrypt_struct  // Lines 144-161
```

Operate on the full struct using trait-based dynamic dispatch (`EncryptStruct`, `DecryptStruct`).

## Future Work

### `drain_from_*` Methods (Planned)

To support the safe fallible operation pattern, `RedoubtVec` and `RedoubtString` will provide:

```rust
impl RedoubtVec<T> {
    /// Drains from slice, zeroizing the source
    pub fn drain_from_slice(&mut self, src: &mut [T]);

    /// Drains from value, zeroizing the source
    pub fn drain_from_value(&mut self, src: &mut T);
}
```

This enables safe atomic updates after leak-operate-commit pattern.

## References

- Struct definition: `crates/redoubt-vault/core/src/cipherbox.rs`
- Main methods: `crates/redoubt-vault/core/src/cipherbox.rs`
- Tests: `crates/redoubt-vault/core/src/tests/cipherbox.rs`
