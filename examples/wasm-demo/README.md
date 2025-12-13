# Redoubt WASM Demo

Demo showcasing Redoubt's `CipherBox` running in WebAssembly.

## Structure

```
wasm-demo/
├── rust/           # Rust WASM library
│   ├── src/
│   │   └── lib.rs  # WASM bindings with wasm-bindgen
│   └── Cargo.toml
├── bun/            # Bun/JavaScript runtime
│   └── main.js     # Test script
├── pkg/            # Generated WASM + JS bindings (gitignored)
└── Makefile.toml   # Build tasks
```

## Prerequisites

- Rust toolchain with `wasm32-unknown-unknown` target:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- [wasm-bindgen-cli](https://rustwasm.github.io/wasm-bindgen/):
  ```bash
  cargo install wasm-bindgen-cli
  ```
- [Bun](https://bun.sh/) runtime
- [cargo-make](https://github.com/sagiegurari/cargo-make):
  ```bash
  cargo install cargo-make
  ```

## Usage

Build and run the demo:
```bash
cargo make run
```

Build only (release):
```bash
cargo make build
```

Build dev version:
```bash
cargo make dev
```

Clean artifacts:
```bash
cargo make clean
```

## What it demonstrates

- `#[cipherbox]` macro generating encrypted storage struct
- `SecretBox::new()` creating encrypted container
- `open_mut()` for safe mutable access to encrypted data
- `open()` for read-only access with verification
- Encryption/decryption roundtrip with assertions
- Automatic zeroization via `MemZer` derive
- Full `no_std` compatibility in WASM environment

## Technical Notes

### Bun Compatibility

This demo includes an automatic workaround for a Bun runtime bug with `WebAssembly.instantiateStreaming`. The build process automatically patches the generated JavaScript to use the slower but more reliable `arrayBuffer()` + `instantiate()` path when running in Bun.

The patch is applied via a Rust script in `Makefile.toml` that runs after `wasm-bindgen` code generation, ensuring compatibility across rebuilds without manual intervention.
