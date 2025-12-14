#!/bin/sh
cargo build --target wasm32-unknown-unknown -p redoubt-aead
cargo build --target wasm32-unknown-unknown -p redoubt-alloc
cargo build --target wasm32-unknown-unknown -p redoubt_rand
cargo build --target wasm32-unknown-unknown -p redoubt-util
cargo build --target wasm32-unknown-unknown -p redoubt-buffer
cargo build --target wasm32-unknown-unknown -p memcodec
cargo build --target wasm32-unknown-unknown -p memcodec_core
cargo build --target wasm32-unknown-unknown -p memcodec_derive
cargo build --target wasm32-unknown-unknown -p redoubt_guard
cargo build --target wasm32-unknown-unknown -p redoubt-secret
cargo build --target wasm32-unknown-unknown -p memzer_core
cargo build --target wasm32-unknown-unknown -p memzer_derive
cargo build --features no_std --target wasm32-unknown-unknown -p memvault
cargo build --features no_std --target wasm32-unknown-unknown -p memvault_core
cargo build --target wasm32-unknown-unknown -p memvault_derive

cargo build --target wasm32-unknown-unknown -p wasm-demo
